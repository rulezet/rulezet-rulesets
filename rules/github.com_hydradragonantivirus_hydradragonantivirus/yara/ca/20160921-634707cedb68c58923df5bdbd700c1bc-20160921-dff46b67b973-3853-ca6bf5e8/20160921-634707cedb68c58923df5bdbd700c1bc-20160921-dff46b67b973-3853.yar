rule _20160921_634707cedb68c58923df5bdbd700c1bc_20160921_dff46b67b973_3853 {
  meta:
    description = "datamaliciousorder - from files 20160921_634707cedb68c58923df5bdbd700c1bc.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152351bec2365a464c735883af22dfe66d59686fad11d1304e9e19accdb6f596"
    hash2       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "0(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";" ascii
    $s2 = "function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "turn \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s4 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f00" ascii
    $s5 = " \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s6 = "return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}