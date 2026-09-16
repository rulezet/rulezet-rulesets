rule sig_20160526_efac9e95640d9a6a91b56cc3a68b7383 {
  meta:
    description = "datamaliciousorder - file 20160526_efac9e95640d9a6a91b56cc3a68b7383.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbd18044c677c880a9cd84ab008a1e06f9a611786a335770396ae700c11ea2d9"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]2z" ascii
    $s2 = "n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(iZOGKXQ noitcnuf\\n\\r;\"is" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}