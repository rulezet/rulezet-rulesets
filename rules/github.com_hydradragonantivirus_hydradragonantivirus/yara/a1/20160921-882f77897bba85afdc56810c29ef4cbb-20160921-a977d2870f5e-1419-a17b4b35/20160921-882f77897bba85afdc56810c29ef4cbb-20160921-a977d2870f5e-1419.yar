rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_a977d2870f5e_1419 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash3       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"

  strings:
    $s1  = "turn \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Sq\";})(),(f" ascii
    $s2  = "f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"NB" ascii
    $s3  = "\"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(funct" ascii
    $s4  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s5  = "{return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})()" ascii
    $s6  = "unction f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii
    $s7  = "{return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(" ascii
    $s8  = "function f000(){return \"Qj\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){retu" ascii
    $s9  = "function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii
    $s10 = "n \"Qj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s11 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s12 = "000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DIa\"" ascii
    $s13 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Qj\";})(),(function f0" ascii
    $s14 = "urn \"Vu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}