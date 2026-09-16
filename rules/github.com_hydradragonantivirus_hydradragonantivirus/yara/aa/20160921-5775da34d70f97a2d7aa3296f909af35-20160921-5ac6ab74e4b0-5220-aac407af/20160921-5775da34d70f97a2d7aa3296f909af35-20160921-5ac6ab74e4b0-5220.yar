rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_5ac6ab74e4b0_5220 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"

  strings:
    $s1 = "),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){" ascii
    $s2 = "n f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"" ascii
    $s3 = " \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(funct" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})()," ascii
    $s5 = "(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}