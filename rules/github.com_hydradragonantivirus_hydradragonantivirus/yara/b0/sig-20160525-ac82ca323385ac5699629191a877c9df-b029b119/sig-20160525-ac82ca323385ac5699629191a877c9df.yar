rule sig_20160525_ac82ca323385ac5699629191a877c9df {
  meta:
    description = "datamaliciousorder - file 20160525_ac82ca323385ac5699629191a877c9df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b194505b4ef088cc4daaf2ff800dee2d48fd92c68da71579725848512aefa3b"

  strings:
    $s1 = "sillock noitcnuf\\n;\"nepf6x\\\\\" = modnark rav\\n;\"56x\\\\07x\\\\y47x\\\\\" = deerdk rav;};ssorcak nruter{)ssorcak(sdnetk noi" ascii
    $s2 = "dari rav;};deerdi nruter{)deerdi(modnari noitcnuf\\n;\"pf6x\\\\\" = sdneti rav\\n;\"e6x\\\\e\" = ssorcai rav;};gsmj nruter{)gsmj" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}