rule sig_20160824_453a5ea86b7604bdf267bb87b1edfebe {
  meta:
    description = "datamaliciousorder - file 20160824_453a5ea86b7604bdf267bb87b1edfebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eec9ca3838fb222ba72f22e391178d506c71c68d45b07dab7432ae53b06e463e"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}