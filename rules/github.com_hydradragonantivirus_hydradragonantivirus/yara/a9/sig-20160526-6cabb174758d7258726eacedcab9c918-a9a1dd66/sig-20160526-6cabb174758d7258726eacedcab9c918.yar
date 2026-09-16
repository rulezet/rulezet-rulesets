rule sig_20160526_6cabb174758d7258726eacedcab9c918 {
  meta:
    description = "datamaliciousorder - file 20160526_6cabb174758d7258726eacedcab9c918.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fe27e9a8673c9d011e262dda91a4b2bb3dbdf2761430754926d2ffad03c7347"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])p" ascii
    $s2 = "cnuf\\n\\r;\"TdaeR\" = 3uXRYYUN rav\\n\\r;\"txe\" = 9jDGVHXU rav\\n\\r;\"solc\" = uSAR rav\\n\\r;\"e\" = 0yVWE rav\\n\\r;\"nel\"" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}