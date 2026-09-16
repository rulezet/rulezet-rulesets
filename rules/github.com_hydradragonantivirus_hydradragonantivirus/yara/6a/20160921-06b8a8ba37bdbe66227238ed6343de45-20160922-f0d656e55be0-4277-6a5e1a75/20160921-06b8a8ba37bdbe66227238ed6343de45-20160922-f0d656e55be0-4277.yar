rule _20160921_06b8a8ba37bdbe66227238ed6343de45_20160922_f0d656e55be0_4277 {
  meta:
    description = "datamaliciousorder - from files 20160921_06b8a8ba37bdbe66227238ed6343de45.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MB" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s3 = "function f000(){return \"Mt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){re" ascii
    $s4 = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Um" ascii
    $s5 = "j\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}