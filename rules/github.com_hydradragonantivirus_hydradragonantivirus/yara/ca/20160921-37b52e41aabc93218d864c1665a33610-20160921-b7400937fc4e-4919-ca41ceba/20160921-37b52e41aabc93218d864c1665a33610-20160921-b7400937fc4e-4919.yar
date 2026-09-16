rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_b7400937fc4e_4919 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(function " ascii
    $s2 = "ion f000(){return \"DYs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return " ascii
    $s4 = "{return \"Wb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})()," ascii
    $s5 = "nction f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}