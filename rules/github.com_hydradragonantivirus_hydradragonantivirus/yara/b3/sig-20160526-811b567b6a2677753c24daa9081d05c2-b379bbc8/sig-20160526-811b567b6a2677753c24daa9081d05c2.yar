rule sig_20160526_811b567b6a2677753c24daa9081d05c2 {
  meta:
    description = "datamaliciousorder - file 20160526_811b567b6a2677753c24daa9081d05c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3696cdbcdfb722833639e79dce1f2c5a9a3db95005b1e619c608571262c8981a"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "aXRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\"" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}