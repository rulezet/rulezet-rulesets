rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_56d2e5a83b59_4401 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"

  strings:
    $s1 = "Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(functio" ascii
    $s2 = "ion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s3 = "000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\"" ascii
    $s4 = "unction f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}