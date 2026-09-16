rule _20160921_5e3ac68b2242250176f3300039d176f6_20160922_99c635a67f89_5261 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash2       = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1 = "\"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s2 = " f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s3 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s4 = "n \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s5 = "nction f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}