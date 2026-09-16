rule sig_20160526_bc80b658e5a7c269fdce7e2a2a7ade99 {
  meta:
    description = "datamaliciousorder - file 20160526_bc80b658e5a7c269fdce7e2a2a7ade99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e9a0e53ab4dad42a9bd131da5ee49985eb2a5e9c6f1e6410c115e24830d5e14"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "XRN nruter{)aXRN(jUZUMBP noitcnuf\\n\\r;\"rw\" = iGPBQMC rav\\n\\r;\"ti\" = pVYV rav\\n\\r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" " ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}