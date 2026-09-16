rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_a56de0614f78_3052 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash3       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s2 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s3 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s4 = "n f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s5 = "000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii
    $s6 = "),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000()" ascii
    $s7 = "h\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}