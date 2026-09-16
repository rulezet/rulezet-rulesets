rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_ec2541ade561_1614 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1  = "\"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(fun" ascii
    $s2  = " \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(func" ascii
    $s3  = "{return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";}" ascii
    $s4  = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb" ascii
    $s5  = "urn \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s6  = "rn \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s7  = "nction f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s8  = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Yv\";})()" ascii
    $s9  = "n f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s10 = " f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe" ascii
    $s11 = "})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f0" ascii
    $s12 = "on f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}