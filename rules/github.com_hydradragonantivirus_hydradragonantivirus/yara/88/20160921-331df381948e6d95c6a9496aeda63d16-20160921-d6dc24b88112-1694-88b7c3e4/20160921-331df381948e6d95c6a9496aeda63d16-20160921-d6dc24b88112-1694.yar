rule _20160921_331df381948e6d95c6a9496aeda63d16_20160921_d6dc24b88112_1694 {
  meta:
    description = "datamaliciousorder - from files 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_d6dc24b88112bfdeca39a6062c7510f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash2       = "b22daaadbd25f5bd920609cbc37e7ea10c4cd99c069220697c4c5db594cffee2"

  strings:
    $s1  = " f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"" ascii
    $s2  = "n\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3  = " f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii
    $s4  = " \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s5  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";}" ascii
    $s6  = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";}" ascii
    $s7  = "0(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";" ascii
    $s8  = "n f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s9  = "n\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s10 = "\"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(func" ascii
    $s11 = "on f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}