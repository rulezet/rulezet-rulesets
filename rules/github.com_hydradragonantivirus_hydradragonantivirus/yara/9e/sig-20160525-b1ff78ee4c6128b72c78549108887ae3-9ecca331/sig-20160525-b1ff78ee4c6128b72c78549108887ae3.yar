rule sig_20160525_b1ff78ee4c6128b72c78549108887ae3 {
  meta:
    description = "datamaliciousorder - file 20160525_b1ff78ee4c6128b72c78549108887ae3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "832514f70048797941c2ccd08ea1a48cca7f7843d55afd0ab5db97199664d9e6"

  strings:
    $s1 = " = ctht rav\\n;\"n56x\\\\\" = rerednert rav\\n;\"96x\\\\27x\\\\w\" = imt rav\\n;\"e47x\\\\\" = eixodu rav\\n;\"x56x\\\\T\" = gsm" ascii
    $s2 = "loco nruter{)dnenoisilloco(suidarelcitrapo noitcnuf\\n;\"56x\\\\l\" = mo rav\\n;\"h47x\\\\gn\" = gedotdaro rav\\n;\"tgn56x\\\\c6" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}