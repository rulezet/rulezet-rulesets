rule sig_20150826_e83f3a035676b488685444c98bf9881b {
  meta:
    description = "datamaliciousorder - file 20150826_e83f3a035676b488685444c98bf9881b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bfaf2e540a30bec555e640585990a7c85eb2c5e59dc337b214c307f70de34c1"

  strings:
    $s1 = "var key = 'cfgr1YRI2uo';var b = '\\x1a6)\\x13X\\x103>y\\x1d\\x16$\\x0f\\x10J\\x11drk\\x5cGZA]jxW,<*F\\x1c\\x00\\x0dF\\x1e\"\\x7f" ascii
    $s2 = "ngth && (DjoUMRTceKYOfUN7 = 0);print(DjoUMRTceKYOfUN5);" fullword ascii
    $s3 = "N5 = \"\", DjoUMRTceKYOfUN6 = 0, DjoUMRTceKYOfUN7 = 0; DjoUMRTceKYOfUN6 < b.length; DjoUMRTceKYOfUN6++) DjoUMRTceKYOfUN5 += Stri" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}