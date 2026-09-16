rule sig_20161111_e597a1a220a517eb2e99565a01804688 {
  meta:
    description = "datamaliciousorder - file 20161111_e597a1a220a517eb2e99565a01804688.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "856b9e5141cd41de88cc92214ec5b27ebe49536506c2b453a44419546d41bb35"

  strings:
    $s1 = "    var JSv3 = [YPu0 + \"hurricanefilters.com/jodu7fb\",YPu0 + \"eddermiaul.net/4hz27zup\",YPu0 + \"kirulya.com/lfmx70p\",YPu0 +" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}