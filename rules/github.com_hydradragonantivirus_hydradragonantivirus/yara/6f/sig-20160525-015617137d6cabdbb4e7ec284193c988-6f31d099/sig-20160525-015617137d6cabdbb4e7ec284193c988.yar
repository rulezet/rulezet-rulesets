rule sig_20160525_015617137d6cabdbb4e7ec284193c988 {
  meta:
    description = "datamaliciousorder - file 20160525_015617137d6cabdbb4e7ec284193c988.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fed117de39a15c37f1986a1fae8b3db515c6816fc7965771f24aaa6c7039273f"

  strings:
    $s1 = "av;\"e\" = deerdp rav;};imp nruter{)imp(rerednerp noitcnuf\\n;\"gn56x\\\\l\" = eixodq rav\\n;\"86x\\\\47x\\\\\" = gsmq rav\\n;\"" ascii
    $s2 = "nard rav\\n;\"r26x\\\\\" = deerdd rav\\n;\"3qf2x\\\\\" = ssorcad rav\\n;\"13x\\\\23x\\\\f\" = tsilslianbmuhtod rav;};rerednerd n" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}