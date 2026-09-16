rule sig_20160525_d4f43deab8d87362f21369e2c88625e8 {
  meta:
    description = "datamaliciousorder - file 20160525_d4f43deab8d87362f21369e2c88625e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "410b7d1907f935ad113a271894fd5e49d002f036f52e88f73e657bc73fbc473f"

  strings:
    $s1 = "dark rav\\n;\"e6x\\\\e\" = keppelk rav;};ssorcak nruter{)ssorcak(sdnetk noitcnuf;};deerdk nruter{)deerdk(modnark noitcnuf\\n;\"4" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}