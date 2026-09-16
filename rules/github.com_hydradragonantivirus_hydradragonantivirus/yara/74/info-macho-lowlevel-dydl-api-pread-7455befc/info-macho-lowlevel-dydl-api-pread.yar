rule INFO_Macho_LowLevel_Dydl_API_pread {
  meta:
    description = "check Macho files for low level API of pread to read from a given input"
    author      = "Greg Lesnewich"
    date        = "2023-01-17"
    version     = "1.0"
    reference   = "https://blog.xpnsec.com/restoring-dyld-memory-loading/"

  strings:
    $ = "pread" ascii wide

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    all of them
}