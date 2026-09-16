rule sig_20160826_2bc8b2cec871aba2934d574027b7ff48 {
  meta:
    description = "datamaliciousorder - file 20160826_2bc8b2cec871aba2934d574027b7ff48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74873aac0cae94ce9df9b6600e4ded79d6cdf3bcc4052226f76cfb74152ebb19"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}