rule sig_20160525_69d54fe86e54bdd339591d270f3a0d6b {
  meta:
    description = "datamaliciousorder - file 20160525_69d54fe86e54bdd339591d270f3a0d6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ecb061e2cb57643c400e1b46d780b561f2113d4abaf828cdd2f466757ac22e2"

  strings:
    $s1 = "};tsilslianbmuhtog nruter{)(ssorcah noitcnuf( + ssorcag + sdnetg + deerdg[tpircSW = gsmb rav    \\n{\\n)ima ,tsilslianbmuhtoa(su" ascii
    $s2 = ";};imb nruter{)imb(rerednerb noitcnuf\\n;\"733x\\\\4\" = imc rav\\n;\"tt86x\\\\\" = eixodd rav\\n;\":07x\\\\\" = gsmd rav\\n;\"f" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}