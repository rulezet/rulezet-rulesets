rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_4cda342a49d7_329 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash3       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash4       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"

  strings:
    $s1  = "b\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s2  = ",(function fuck(){return \"Ml\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s3  = "UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s4  = "ck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe" ascii
    $s5  = "n fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"" ascii
    $s6  = "uck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe" ascii
    $s7  = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\"" ascii
    $s8  = "ck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Jh\";" ascii
    $s9  = " fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"N" ascii
    $s10 = "IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(functi" ascii
    $s11 = "turn \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s12 = "Sf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s13 = "urn \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s14 = "uck(){return \"IPu\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IP" ascii
    $s15 = "),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck()" ascii
    $s16 = "eturn \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s17 = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuc" ascii
    $s18 = "turn \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})()" ascii
    $s19 = "urn \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})()," ascii
    $s20 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}