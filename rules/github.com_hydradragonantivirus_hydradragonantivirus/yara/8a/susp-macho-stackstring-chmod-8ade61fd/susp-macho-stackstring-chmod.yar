rule SUSP_Macho_StackString_chmod {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for the string chmod being passed as a stack string"

  strings:
    $chmod = { 4? ?? 63 68 6d 6f 64 4? }  
  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}