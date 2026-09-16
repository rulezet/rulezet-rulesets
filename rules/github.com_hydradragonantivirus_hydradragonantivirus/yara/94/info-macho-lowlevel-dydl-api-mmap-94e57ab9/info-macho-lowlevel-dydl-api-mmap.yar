rule INFO_Macho_LowLevel_Dydl_API_mmap {
  meta:
    description = "check Macho files for low level API of mmap to map a file into memory"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "mmap" ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}