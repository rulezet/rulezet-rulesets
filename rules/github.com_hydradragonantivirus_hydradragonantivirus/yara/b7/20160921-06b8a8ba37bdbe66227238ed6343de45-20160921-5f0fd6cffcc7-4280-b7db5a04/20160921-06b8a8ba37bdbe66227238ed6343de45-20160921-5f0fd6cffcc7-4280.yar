rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_5f0fd6cffcc7_4280 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(" ascii
    $s2 = "nction f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s3 = " f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"R" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}