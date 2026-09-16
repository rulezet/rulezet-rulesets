rule sig_20160826_5c97ce6b78e456764b71081ecec28a44 {
  meta:
    description = "datamaliciousorder - file 20160826_5c97ce6b78e456764b71081ecec28a44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4346ce77fb3b8be469a2c7727089974105d0acffc2bad269cd57b29a1fcef982"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}