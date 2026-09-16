rule SUSP_Macho_StackString_TAR {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-18"
    version     = "1.0"
    description = "check for the string tar zxvf or just tar  being passed as a stack string"

  strings:
    $tar_zxvf = { 4? ?? 74 61 72 20 7a 78 76 66 4? }      $tar_zxf  = { 4? ?? 74 61 72 20 7a 78 66 4? }

  condition:
    (uint32be(0x0) == 0xCAFEBABE or uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    1 of them
}