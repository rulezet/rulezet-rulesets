rule sig_20160526_8f7369e5d1dc3e3fcaa14faa56f44cd3 {
  meta:
    description = "datamaliciousorder - file 20160526_8f7369e5d1dc3e3fcaa14faa56f44cd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e478cfa5c184917e58b9172f92edd34762ce94164f058814c6036e00303d78eb"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]6w" ascii
    $s2 = "};aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}