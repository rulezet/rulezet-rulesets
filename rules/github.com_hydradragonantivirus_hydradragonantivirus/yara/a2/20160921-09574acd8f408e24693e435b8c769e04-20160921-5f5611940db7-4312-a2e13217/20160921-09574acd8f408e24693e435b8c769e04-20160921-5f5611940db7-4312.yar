rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_5f5611940db7_4312 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash3       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"

  strings:
    $s1 = "eturn \"Wy\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s2 = " f000(){return \"QDg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"G" ascii
    $s3 = "a\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yz\";})(),(function f" ascii
    $s4 = "\"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(funct" ascii
    $s5 = "),(function f000(){return \"BIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}