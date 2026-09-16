rule sig_20160526_8cf95588c7a87131e2dc4a737a3d6827 {
  meta:
    description = "datamaliciousorder - file 20160526_8cf95588c7a87131e2dc4a737a3d6827.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4006a4be835829bc7bacee81e59134815bbffe2d9918c51fa9002e748bcf0873"

  strings:
    $s1 = "STAW rav\\n\\r;]iDJW + fNSF+dBQGQHT+xTHIZDE + cMJHHOA+gVVBHIQ+)7pFPDPMM(9mRDT+7sSZOWED + lRVZUFH+7wYWW + dBBZ+))(};lPYH nruter{)" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}