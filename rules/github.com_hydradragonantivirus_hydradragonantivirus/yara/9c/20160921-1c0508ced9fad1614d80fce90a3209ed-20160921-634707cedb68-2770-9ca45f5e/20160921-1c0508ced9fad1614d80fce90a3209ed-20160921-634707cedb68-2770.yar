rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_634707cedb68_2770 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_634707cedb68c58923df5bdbd700c1bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"

  strings:
    $s1 = "rn \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"TRc\";" ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs" ascii
    $s4 = "nction f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retu" ascii
    $s5 = "unction f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s6 = "){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(" ascii
    $s7 = "KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}