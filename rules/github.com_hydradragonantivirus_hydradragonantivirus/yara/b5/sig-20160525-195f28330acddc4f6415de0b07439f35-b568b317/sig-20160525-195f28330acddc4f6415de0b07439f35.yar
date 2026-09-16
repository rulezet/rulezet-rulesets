rule sig_20160525_195f28330acddc4f6415de0b07439f35 {
  meta:
    description = "datamaliciousorder - file 20160525_195f28330acddc4f6415de0b07439f35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "418a0940a36579638d19c178eff94a1fb1cdbf1c36deb0709694dc457f760d66"

  strings:
    $s1 = "nark rav;\"vhM6S5\" = gedotdark rav\\n;\"e37x\\\\\" = deerdk rav\\n;\"46x\\\\n\" = sdnetk rav\\n;\"56x\\\\ec6x\\\\35x\\\\\" = ss" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}