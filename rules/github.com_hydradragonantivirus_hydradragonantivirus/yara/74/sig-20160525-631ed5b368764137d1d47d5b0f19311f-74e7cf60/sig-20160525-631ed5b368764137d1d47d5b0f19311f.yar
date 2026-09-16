rule sig_20160525_631ed5b368764137d1d47d5b0f19311f {
  meta:
    description = "datamaliciousorder - file 20160525_631ed5b368764137d1d47d5b0f19311f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4307d7b9904d63e8ca3e2cb6619440eac58f83e3225e96a80b01a24d1eec20e"

  strings:
    $s1 = "[eixodj = suidarelcitrapj rav;\"Tp\" = eixodj rav;};mj nruter{)mj(dnenoisillocj noitcnuf\\n;\"56x\\\\07x\\\\o\" = keppelj rav\\n" ascii
    $s2 = "rapt rav;};mt nruter{)mt(dnenoisilloct noitcnuf\\n;\"16x\\\\e25x\\\\\" = gedotdart rav\\n;\"tx56x\\\\Td\" = keppelt rav\\n;\"oc6" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}