rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_99d82d332144_3404 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = "0(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";" ascii
    $s2 = "0(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s3 = "\"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s4 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";}" ascii
    $s5 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"K" ascii
    $s6 = "v\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}