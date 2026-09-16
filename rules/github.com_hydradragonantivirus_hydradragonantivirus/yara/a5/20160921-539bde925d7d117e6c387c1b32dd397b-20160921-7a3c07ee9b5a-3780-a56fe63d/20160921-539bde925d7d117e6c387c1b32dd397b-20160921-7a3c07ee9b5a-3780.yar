rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_7a3c07ee9b5a_3780 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = "(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000()" ascii
    $s2 = "(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DYx\";})(),(function f000(){" ascii
    $s3 = "function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){re" ascii
    $s4 = "n \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5 = "){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";" ascii
    $s6 = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qa\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}