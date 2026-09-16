rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_5f5611940db7_4188 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Go\";})(),(function f0" ascii
    $s2 = "),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s3 = "on f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s4 = "eturn \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5 = "turn \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TKl\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}