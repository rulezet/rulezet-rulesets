rule sig_20160525_fc128b0d07ec9c127fc4c203fc6f8ffc {
  meta:
    description = "datamaliciousorder - file 20160525_fc128b0d07ec9c127fc4c203fc6f8ffc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fe3deda66501fafc84ad5c39070c03815312f1d0d5891f786779d06b3a23767"

  strings:
    $s1 = "rdd noitcnuf( + ecapsetihwxelfd+keppeld + gedotdard+suidarelcitrapd + gsmd+eixodd[ = rerednera rav\\n\\n;\"734\" = mb rav\\n;2 =" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}