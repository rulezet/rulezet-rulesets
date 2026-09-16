rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_6d9213179dbb_5212 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash3       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash4       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()];" fullword ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s3 = "rn \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(fu" ascii
    $s4 = "{return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";}" ascii
    $s5 = "00(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}