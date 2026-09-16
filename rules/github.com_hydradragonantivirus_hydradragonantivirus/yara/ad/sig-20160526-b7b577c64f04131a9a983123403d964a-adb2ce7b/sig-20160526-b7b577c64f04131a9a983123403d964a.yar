rule sig_20160526_b7b577c64f04131a9a983123403d964a {
  meta:
    description = "datamaliciousorder - file 20160526_b7b577c64f04131a9a983123403d964a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc4ccd5b88fc020755d15ebdb601abfc937706585dd5284eb7830b65944353ae"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]cT" ascii
    $s2 = "r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(iZO" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}