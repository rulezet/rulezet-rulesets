rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_be882ab89423_2914 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1 = "(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})" ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){retur" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(func" ascii
    $s4 = "n \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5 = ";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000" ascii
    $s6 = "f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"D" ascii
    $s7 = "tion f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}