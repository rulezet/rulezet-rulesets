rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160922_b22dda4c9fbc_4440 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s2 = " f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"G" ascii
    $s3 = "rn \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(fu" ascii
    $s4 = "ction f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s5 = "),(function f000(){return \"BMj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}