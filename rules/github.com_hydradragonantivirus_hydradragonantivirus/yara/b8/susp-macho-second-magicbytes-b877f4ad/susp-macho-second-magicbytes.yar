rule SUSP_Macho_Second_MagicBytes {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-02-04"
    version     = "1.0"
    description = "check Macho samples for additional Macho magic bytes"

  strings:
    $CFFAEDFE = { CF FA ED FE }
    $CEFAEDFE = { CE FA ED FE }

  condition:
    (uint32be(0x0) == 0xCFFAEDFE or uint32be(0x0) == 0xCEFAEDFE) and
    (#CFFAEDFE >= 2 or #CEFAEDFE >= 2)
}