rule sig_20160526_cf8a95bed782d99aa309fffc1082a1b6 {
  meta:
    description = "datamaliciousorder - file 20160526_cf8a95bed782d99aa309fffc1082a1b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e92ccdd3e5f37ca9dacc2839770e0ec256181ca214d771f7dfb8fbb3ecccd684"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]cT" ascii
    $s2 = "r;\"e\" = 8zQLOFVP rav\\n\\r;\"opseR\" = tARO rav\\n\\r;\"oBesn\" = 8aVRMINY rav\\n\\r;\"yd\" = qDYF rav;};wFEA nruter{)wFEA(iZO" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}