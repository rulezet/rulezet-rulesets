rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_5eea6af1c50b_1990 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_5eea6af1c50b807f547cb710eb413110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"

  strings:
    $s1 = "urn \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s2 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s4 = "urn \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5 = "g\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function" ascii
    $s6 = "ction f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s7 = "Ts\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s8 = "Tn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s9 = "function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}