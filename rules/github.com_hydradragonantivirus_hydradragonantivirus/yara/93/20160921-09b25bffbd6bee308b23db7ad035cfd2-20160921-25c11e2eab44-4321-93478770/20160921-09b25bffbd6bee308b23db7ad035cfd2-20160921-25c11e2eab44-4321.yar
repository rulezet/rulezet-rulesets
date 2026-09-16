rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_25c11e2eab44_4321 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"

  strings:
    $s1 = "on f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2 = "f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc" ascii
    $s3 = "000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg" ascii
    $s4 = "nction f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s5 = "{return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}