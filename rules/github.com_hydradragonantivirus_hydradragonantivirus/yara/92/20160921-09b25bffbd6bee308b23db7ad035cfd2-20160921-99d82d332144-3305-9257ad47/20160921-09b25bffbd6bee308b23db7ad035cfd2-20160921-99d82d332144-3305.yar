rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_99d82d332144_3305 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_99d82d33214407e421e255b85f02daae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"

  strings:
    $s1 = "w\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s2 = "(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii
    $s3 = "tion f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s4 = "0(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s5 = "000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz" ascii
    $s6 = "\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}