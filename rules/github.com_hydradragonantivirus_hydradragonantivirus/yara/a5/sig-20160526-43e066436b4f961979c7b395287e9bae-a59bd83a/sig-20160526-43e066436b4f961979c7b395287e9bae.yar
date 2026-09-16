rule sig_20160526_43e066436b4f961979c7b395287e9bae {
  meta:
    description = "datamaliciousorder - file 20160526_43e066436b4f961979c7b395287e9bae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58181d0e306b1c44f23929f6ae2258db78b5bd6686e47e841c07cb445d817bf5"

  strings:
    $s1 = "\"Ff6x\\\\\" = d7lRKICLO rav\\n;\"c6x\\\\i\" = z2cVJATDE rav\\n;\"56x\\\\\" = e8gFNVXRP rav\\n;\"56x\\\\solc\" = p2pGREVCV rav'[" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}