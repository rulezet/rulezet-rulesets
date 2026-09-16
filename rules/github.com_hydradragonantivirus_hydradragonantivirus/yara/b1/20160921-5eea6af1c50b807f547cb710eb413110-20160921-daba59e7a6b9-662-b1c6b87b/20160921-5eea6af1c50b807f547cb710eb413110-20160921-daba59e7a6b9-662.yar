rule _20160921_5eea6af1c50b807f547cb710eb413110_20160921_daba59e7a6b9_662 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "0(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\"" ascii
    $s2  = "),(function f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s3  = "eturn \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4  = "00(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\"" ascii
    $s5  = "(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000()" ascii
    $s6  = "(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"OUx\";})(),(function f000(){r" ascii
    $s7  = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"EZu\";})(),(fun" ascii
    $s8  = "g\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f" ascii
    $s9  = "on f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s10 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s11 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wy\";})(),(function f000" ascii
    $s12 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})" ascii
    $s13 = "f000(){return \"MJq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"P" ascii
    $s14 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Km\";})" ascii
    $s15 = "Dg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function" ascii
    $s16 = "),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(" ascii
    $s17 = "{return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"MMz\";})(" ascii
    $s18 = "(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){re" ascii
    $s19 = "0(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\"" ascii
    $s20 = "000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}