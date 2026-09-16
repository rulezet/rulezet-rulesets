rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_87f13d652177_4633 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_87f13d652177c2ccba1196dd341efb6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "52cce778f06a6477b6f4a6a9f48328a81d874164235533c2925fdd358b6279c3"

  strings:
    $s1 = "),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000()" ascii
    $s2 = "return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s3 = " \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(fun" ascii
    $s4 = "\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function " ascii
    $s5 = "function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}