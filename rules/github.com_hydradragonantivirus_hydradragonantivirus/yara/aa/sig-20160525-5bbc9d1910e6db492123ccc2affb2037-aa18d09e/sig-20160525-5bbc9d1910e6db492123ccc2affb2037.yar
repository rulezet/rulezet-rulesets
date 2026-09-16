rule sig_20160525_5bbc9d1910e6db492123ccc2affb2037 {
  meta:
    description = "datamaliciousorder - file 20160525_5bbc9d1910e6db492123ccc2affb2037.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "574a2c9828f833ab14a7d0afde15ccb6371e7fbdf8a1aa3f1895544f7fb47064"

  strings:
    $s1 = "= modnar rav\\n;)imf + rerednerf + cthf + tsilslianbmuhtof + ssorcaf(]))(};mf nruter{)(gedotdarf noitcnuf( + dnenoisillocf + sui" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}