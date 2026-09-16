rule sig_20160822_3bea2f0842bde199f6866c572121f252 {
  meta:
    description = "datamaliciousorder - file 20160822_3bea2f0842bde199f6866c572121f252.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67ec9839605fc9094542d0e510a57dcff7ff020f4580513f02bd7758aa5cb808"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}