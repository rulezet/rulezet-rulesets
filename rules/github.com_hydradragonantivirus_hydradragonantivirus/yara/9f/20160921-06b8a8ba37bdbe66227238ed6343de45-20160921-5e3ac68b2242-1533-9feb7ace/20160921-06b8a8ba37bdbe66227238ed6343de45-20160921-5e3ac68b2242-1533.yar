rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160921_5e3ac68b2242_1533 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160921_5e3ac68b2242250176f3300039d176f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"

  strings:
    $s1  = "eturn \"KDh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s2  = "function f000(){return \"SGs\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3  = "){return \"Sj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s4  = " f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s5  = "tion f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s6  = "\"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s7  = "(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(" ascii
    $s8  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DAp" ascii
    $s9  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"PTs" ascii
    $s10 = "function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s11 = "){return \"Rh\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(" ascii
    $s12 = "Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}