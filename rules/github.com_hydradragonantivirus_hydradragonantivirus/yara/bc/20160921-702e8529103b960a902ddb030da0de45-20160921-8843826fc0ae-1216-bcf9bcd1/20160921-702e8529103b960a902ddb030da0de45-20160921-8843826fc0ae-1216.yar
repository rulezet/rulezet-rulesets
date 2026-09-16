rule _20160921_702e8529103b960a902ddb030da0de45_20160921_8843826fc0ae_1216 {
  meta:
    description = "datamaliciousorder - from files 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_8843826fc0ae466921b7811b54d8314e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash2       = "78595fd8fc9b77e9ad7cb382c7d0ec855211116626b883d04155604a9a99eab3"

  strings:
    $s1  = "(){return \"Sq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";" ascii
    $s2  = "})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s3  = "nction f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"EZu\";})(),(function f000(){retu" ascii
    $s4  = "function f000(){return \"SEo\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s5  = "b\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s6  = "tion f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){retur" ascii
    $s7  = "),(function f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000()" ascii
    $s8  = "\"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s9  = "n \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s10 = "000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb" ascii
    $s11 = "{return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})" ascii
    $s12 = "tion f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return" ascii
    $s13 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f0" ascii
    $s14 = "n \"UEg\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s15 = "(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";" ascii
    $s16 = "eturn \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"TKp\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}