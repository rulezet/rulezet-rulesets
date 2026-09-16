rule sig_20160525_5b152386696dad68069f2e74227ebe63 {
  meta:
    description = "datamaliciousorder - file 20160525_5b152386696dad68069f2e74227ebe63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40baf10540d2372406f30d7ec3f424a26e57f519c6dda6c23b30302881fb2206"

  strings:
    $s1 = "rape rav\\n;\"f2x\\\\f2x\\\\\" = me rav\\n;\"47x\\\\i\" = gedotdare rav\\n;\"f6x\\\\nk\" = keppele rav\\n;\"oh77x\\\\\" = deerde" ascii
    $s2 = "loci rav;};keppeli nruter{)keppeli(gedotdari noitcnuf\\n;\"LMXSd4x\\\\\" = ecapsetihwxelfi rav\\n;\"MXe2x\\\\23x\\\\\" = modnari" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}