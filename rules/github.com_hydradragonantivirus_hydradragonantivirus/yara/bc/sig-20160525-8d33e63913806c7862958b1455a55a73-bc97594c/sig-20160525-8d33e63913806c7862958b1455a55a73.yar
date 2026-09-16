rule sig_20160525_8d33e63913806c7862958b1455a55a73 {
  meta:
    description = "datamaliciousorder - file 20160525_8d33e63913806c7862958b1455a55a73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00593e26f4da8deb786641cb13e8553b37593464faccb50fa5659db8968b2f40"

  strings:
    $s1 = "itcnuf\\n;\"dn96x\\\\w\" = imn rav\\n;\"wf6x\\\\\" = eixodo rav\\n;\"523x\\\\13x\\\\-37x\\\\\" = gsmo rav\\n;)5(]\"tAra\"+\"86x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}