rule sig_20160525_3a5f867e7cf1cfe6e733bddc0548aee3 {
  meta:
    description = "datamaliciousorder - file 20160525_3a5f867e7cf1cfe6e733bddc0548aee3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9217de1f03707ca5d34dc8bfe1ae94cf5b85d42597ee4486d686695d0fa48db"

  strings:
    $s1 = "\"doB56x\\\\\" = cthl rav\\n;\"97x\\\\\" = rerednerl rav;};eixodm nruter{)eixodm(iml noitcnuf\\n;\"47x\\\\isop\" = gsmm rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}