rule _20160921_61ffae07802bf5013fbbf8f137c827c3_20160921_8d22ed47876b_838 {
  meta:
    description = "datamaliciousorder - from files 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_8d22ed47876b303a1415a88483556238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"

  strings:
    $s1  = "eturn \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})()," ascii
    $s2  = " \"MKa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3  = "rn \"IPu\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(f" ascii
    $s4  = "),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s5  = "urn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s6  = "function f000(){return \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s7  = "{return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s8  = "n \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(func" ascii
    $s9  = "0(){return \"QDg\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg" ascii
    $s10 = "(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})" ascii
    $s11 = ";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s12 = "turn \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(" ascii
    $s13 = "unction f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s14 = "tion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retur" ascii
    $s15 = "00(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZGq" ascii
    $s16 = "unction f000(){return \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){ret" ascii
    $s17 = "0(){return \"MKa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\"" ascii
    $s18 = "{return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})()" ascii
    $s19 = "on f000(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s20 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}