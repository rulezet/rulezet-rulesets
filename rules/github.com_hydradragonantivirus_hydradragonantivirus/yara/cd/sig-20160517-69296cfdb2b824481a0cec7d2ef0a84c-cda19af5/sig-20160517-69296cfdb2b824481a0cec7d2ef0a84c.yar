rule sig_20160517_69296cfdb2b824481a0cec7d2ef0a84c {
  meta:
    description = "datamaliciousorder - file 20160517_69296cfdb2b824481a0cec7d2ef0a84c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a84de7fb3321b9e12b33f9eeaa711bd3cc547fbfa8c2f3e17926d751bf3c46"

  strings:
    $s1 = "var vfvxwy='vhtkv2ahdgd3razesn pdtrgjiobrcersjsqrm2jaxyhjbuqyh4qmwbmn42fqdoxpgquz4ns1tduciroqwxl=ncpds\\'qlfpmto4bmscnqsqdnyjlgq" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}