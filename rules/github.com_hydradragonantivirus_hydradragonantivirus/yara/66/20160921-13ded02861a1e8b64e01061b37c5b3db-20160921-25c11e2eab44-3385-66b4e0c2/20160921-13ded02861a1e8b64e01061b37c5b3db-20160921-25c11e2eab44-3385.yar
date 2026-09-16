rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_25c11e2eab44_3385 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_25c11e2eab44b5e0380e0bd805a72790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"

  strings:
    $s1 = " f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj" ascii
    $s2 = "0(){return \"ZIi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "urn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s4 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(fun" ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(fu" ascii
    $s6 = "(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}