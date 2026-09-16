rule sig_20160526_c9ec4aa21f8ca98f00bb170e00c8f62c {
  meta:
    description = "datamaliciousorder - file 20160526_c9ec4aa21f8ca98f00bb170e00c8f62c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d794fcda6b9fae53be10f00db4ac069ab8c498fa7b530e0c39e0a551c0958611"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]))" ascii
    $s2 = ")5uNNTINF(1kSJC noitcnuf\\n\\r;\"nepo\" = oAST rav\\n\\r;\"FdaoL\" = 9gJSN rav\\n\\r;\"or\" = yBUVVQB rav\\n\\r;\"liFm\" = vRWQ " ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}