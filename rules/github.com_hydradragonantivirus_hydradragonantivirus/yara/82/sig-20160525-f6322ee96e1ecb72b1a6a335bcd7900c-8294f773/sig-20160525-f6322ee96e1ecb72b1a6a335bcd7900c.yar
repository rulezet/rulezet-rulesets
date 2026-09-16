rule sig_20160525_f6322ee96e1ecb72b1a6a335bcd7900c {
  meta:
    description = "datamaliciousorder - file 20160525_f6322ee96e1ecb72b1a6a335bcd7900c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d841957a79365a145acc973c04645154465858663eee6bcc7aaf2fb52fae0255"

  strings:
    $s1 = "rk rav\\n;\"e37x\\\\\" = keppelk rav\\n;\"46x\\\\n\" = ecapsetihwxelfk rav\\n;\"l35x\\\\\" = deerdk rav\\n;\"56x\\\\56x\\\\\" = " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}