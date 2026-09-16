rule _20160921_17bab7cc945fd06123e7b9b16dea263f_20160922_c593174721c6_149 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bab7cc945fd06123e7b9b16dea263f.js, 20160922_c593174721c6fbd1b57bf98d8a85a6fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1dd80ed4e2509af999afcf84c8f78ecc409616f9d6e072d25cb980d8bf9e464"
    hash2       = "c85cab0d5b0c79fe38ee2b60c2ea7eca36bb7dbe9442cff0a497346184cecee8"

  strings:
    $s1  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s2  = "ZGq\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s3  = "n f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii
    $s4  = "n \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s5  = "eturn \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})()," ascii
    $s6  = "\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f" ascii
    $s7  = "00(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq" ascii
    $s8  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(function f000" ascii
    $s9  = "})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"ZGq\";})(),(function f0" ascii
    $s10 = "urn \"Yv\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s11 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"ZFe\";})(),(" ascii
    $s12 = "\"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s13 = "n \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(fu" ascii
    $s14 = "eturn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})()" ascii
    $s15 = "00(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc" ascii
    $s16 = "n \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s17 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s18 = ")(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(" ascii
    $s19 = " f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"" ascii
    $s20 = "q\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}