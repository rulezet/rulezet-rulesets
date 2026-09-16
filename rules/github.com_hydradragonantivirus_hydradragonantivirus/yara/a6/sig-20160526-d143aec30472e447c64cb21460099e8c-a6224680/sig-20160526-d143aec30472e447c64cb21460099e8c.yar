rule sig_20160526_d143aec30472e447c64cb21460099e8c {
  meta:
    description = "datamaliciousorder - file 20160526_d143aec30472e447c64cb21460099e8c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6dbb1b4793ad43d42085820b4cc46424f624655e5fd930be0c03bce230658b58"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])p" ascii
    $s2 = "nuf\\n\\r;\"TdaeR\" = 3uXRYYUN rav\\n\\r;\"txe\" = 9jDGVHXU rav\\n\\r;\"solc\" = uSAR rav\\n\\r;\"e\" = 0yVWE rav\\n\\r;\"nel\" " ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}