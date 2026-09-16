rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_dd666c66b3f1_5109 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "eturn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})()" ascii
    $s2 = "eturn \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})()" ascii
    $s3 = "),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s4 = "(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s5 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}