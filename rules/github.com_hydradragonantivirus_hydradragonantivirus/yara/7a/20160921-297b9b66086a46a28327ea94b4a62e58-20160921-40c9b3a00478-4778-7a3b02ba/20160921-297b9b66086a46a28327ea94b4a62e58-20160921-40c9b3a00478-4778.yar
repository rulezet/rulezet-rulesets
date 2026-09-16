rule _20160921_297b9b66086a46a28327ea94b4a62e58_20160921_40c9b3a00478_4778 {
  meta:
    description = "datamaliciousorder - from files 20160921_297b9b66086a46a28327ea94b4a62e58.js, 20160921_40c9b3a004789873984432b531f4fb80.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d719bbec78475fb1d00242f1258699600032a10dd821cc9dfec2254bbe341f7"
    hash2       = "b913ca9b6976b1846b7d36cab5b8fc09147f8eda84e9fde77f0aab4dfe5a2ab3"
    hash3       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash4       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"

  strings:
    $s1 = " \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(functi" ascii
    $s2 = "{return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})()" ascii
    $s3 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(functi" ascii
    $s4 = "on f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s5 = "00(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}