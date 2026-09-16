rule sig_20160525_28cf455155b91ffd5399e303ea73e1b6 {
  meta:
    description = "datamaliciousorder - file 20160525_28cf455155b91ffd5399e303ea73e1b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3806df09c355e090c91b0d2c7271372fdc9c6f012b853030d1e481caa0e9a98"

  strings:
    $s1 = "itcnuf\\n;\"dn96x\\\\w\" = imn rav\\n;\"wf6x\\\\\" = eixodo rav\\n;\"523x\\\\13x\\\\-37x\\\\\" = gsmo rav\\n;)5(]\"tAra\"+\"86x" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}