rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_ded524cdc972_3354 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Mc\";})(),(function f000(){" ascii
    $s2 = "rn \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s3 = "nction f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s4 = "return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})()," ascii
    $s5 = " \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s6 = "\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MBb\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}