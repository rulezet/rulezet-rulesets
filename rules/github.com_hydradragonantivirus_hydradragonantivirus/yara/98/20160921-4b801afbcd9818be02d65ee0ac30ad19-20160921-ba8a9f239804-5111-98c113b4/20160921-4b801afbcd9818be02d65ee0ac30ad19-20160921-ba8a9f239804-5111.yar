rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_ba8a9f239804_5111 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js, 20160921_ee1327bdf201e62d1f7ae5482cabbd90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"
    hash3       = "91500ac726f9d2548dffc99162aeece9863dc7b928106d27a769e6bbf9439f81"

  strings:
    $s1 = "rn \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s2 = "{return \"BQb\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";}" ascii
    $s3 = "Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(functi" ascii
    $s4 = "){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})" ascii
    $s5 = "\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}