rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_f11c35e31593_4991 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "00(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn" ascii
    $s2 = "rn \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = "ion f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s4 = "n \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s5 = "00(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}