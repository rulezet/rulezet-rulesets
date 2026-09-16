rule sig_20160525_9ea1f5455621680c77ef768d15152c70 {
  meta:
    description = "datamaliciousorder - file 20160525_9ea1f5455621680c77ef768d15152c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22713af3820d05a4b463a88af0c01f474af33c8651b22b2967e835c9b7d19737"

  strings:
    $s1 = "dare rav;};ecapsetihwxelfe nruter{)ecapsetihwxelfe(keppele noitcnuf\\n;\"16x\\\\56x\\\\rC\" = deerde rav\\n;\"e47x\\\\\" = sdnet" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}