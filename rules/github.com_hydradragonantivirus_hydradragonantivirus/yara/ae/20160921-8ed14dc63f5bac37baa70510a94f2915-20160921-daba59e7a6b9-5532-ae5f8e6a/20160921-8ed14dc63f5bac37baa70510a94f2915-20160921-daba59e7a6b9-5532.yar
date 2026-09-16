rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_daba59e7a6b9_5532 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "unction f000(){return \"Vj\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s2 = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TKl\";})(),(function" ascii
    $s3 = "unction f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){re" ascii
    $s4 = "\"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s5 = "XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}