rule sig_20160525_b9fd53446a3c9bda7bfb28166d1d053e {
  meta:
    description = "datamaliciousorder - file 20160525_b9fd53446a3c9bda7bfb28166d1d053e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73de860cdfdf0a0ade2dd908fbec35dd08279770c88f796eb18d235d5e6231c6"

  strings:
    $s1 = " = ctht rav\\n;\"n56x\\\\\" = rerednert rav\\n;\"96x\\\\27x\\\\w\" = imt rav\\n;\"e47x\\\\\" = eixodu rav\\n;\"x56x\\\\T\" = gsm" ascii
    $s2 = "loco nruter{)dnenoisilloco(suidarelcitrapo noitcnuf\\n;\"56x\\\\l\" = mo rav\\n;\"h47x\\\\gn\" = gedotdaro rav\\n;\"tgn56x\\\\c6" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}