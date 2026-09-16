rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_4b801afbcd98_4604 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_4b801afbcd9818be02d65ee0ac30ad19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"

  strings:
    $s1 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";" ascii
    $s2 = "\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f" ascii
    $s3 = "(function f000(){return \"Yz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s4 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5 = "(){return \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}