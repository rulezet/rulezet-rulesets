rule _20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3_20160921_ec2541ade561_1933 {
  meta:
    description = "datamaliciousorder - from files 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1  = "\"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(func" ascii
    $s2  = "(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){r" ascii
    $s3  = "urn \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s4  = "ction f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5  = "n f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"G" ascii
    $s6  = "n \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s7  = ")(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000" ascii
    $s8  = "n \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s9  = "\"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s10 = "f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}