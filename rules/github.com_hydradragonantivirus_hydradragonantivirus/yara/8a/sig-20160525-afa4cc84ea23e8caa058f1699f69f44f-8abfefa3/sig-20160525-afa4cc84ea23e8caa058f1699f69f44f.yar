rule sig_20160525_afa4cc84ea23e8caa058f1699f69f44f {
  meta:
    description = "datamaliciousorder - file 20160525_afa4cc84ea23e8caa058f1699f69f44f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060f1954b74f0cab0d25d399812349439091d380758d2296faed82d1cfeab402"

  strings:
    $s1 = "b[ = ctha rav\\n\\n;\"734\" = mb rav\\n;2041 + 0041- = deerda rav\\n;2 = tsilslianbmuhtoa rav\\n;1 = deerd rav\\n\\n;2037 - 5248" ascii
    $s2 = "rapt rav;\"2teI7H\" = eixodt rav\\n;\"27x\\\\ahC\" = dnenoisilloct rav\\n;\"t56x\\\\s\" = mt rav\\n;\"07x\\\\f6x\\\\\" = gedotda" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}