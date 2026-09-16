rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_702e8529103b_1964 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_702e8529103b960a902ddb030da0de45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"

  strings:
    $s1 = "(function f000(){return \"Tb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){r" ascii
    $s2 = "return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})()," ascii
    $s3 = "(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){ret" ascii
    $s4 = "(function f000(){return \"IPu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s5 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(fu" ascii
    $s6 = "Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function" ascii
    $s7 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(fun" ascii
    $s8 = "n \"Um\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s9 = "0(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}