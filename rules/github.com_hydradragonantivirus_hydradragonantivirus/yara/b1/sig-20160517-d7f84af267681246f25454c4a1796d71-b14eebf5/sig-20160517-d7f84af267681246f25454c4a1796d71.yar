rule sig_20160517_d7f84af267681246f25454c4a1796d71 {
  meta:
    description = "datamaliciousorder - file 20160517_d7f84af267681246f25454c4a1796d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf34ea315654908ac366bcd5cba7990726cb99a6935c7e741a57e5c20c1de166"

  strings:
    $s1 = "var w2akl='vnqif3akfmhsrinltx ogxylql2hwbewffzgods2e3sduipbpr2tpvyszcnyqeaz42frmgllcjhesq=rvksl\\'lwnjmtm4mpqcwgukknop1cbigwmuof" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}