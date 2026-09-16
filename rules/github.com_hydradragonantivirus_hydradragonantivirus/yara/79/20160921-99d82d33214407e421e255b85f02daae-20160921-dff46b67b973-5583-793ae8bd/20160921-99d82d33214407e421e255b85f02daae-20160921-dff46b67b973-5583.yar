rule _20160921_99d82d33214407e421e255b85f02daae_20160921_dff46b67b973_5583 {
  meta:
    description = "datamaliciousorder - from files 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s2 = "n \"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(func" ascii
    $s3 = "000(){return \"Ot\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\"" ascii
    $s4 = "tion f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii
    $s5 = "{return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}