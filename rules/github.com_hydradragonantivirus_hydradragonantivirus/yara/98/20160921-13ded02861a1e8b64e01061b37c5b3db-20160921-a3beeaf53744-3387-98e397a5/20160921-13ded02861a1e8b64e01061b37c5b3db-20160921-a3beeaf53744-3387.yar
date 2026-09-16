rule _20160921_13ded02861a1e8b64e01061b37c5b3db_20160921_a3beeaf53744_3387 {
  meta:
    description = "datamaliciousorder - from files 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash3       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "n \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(fun" ascii
    $s2 = "on f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s3 = "00(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTs" ascii
    $s4 = " f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj" ascii
    $s5 = "turn \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s6 = "function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}