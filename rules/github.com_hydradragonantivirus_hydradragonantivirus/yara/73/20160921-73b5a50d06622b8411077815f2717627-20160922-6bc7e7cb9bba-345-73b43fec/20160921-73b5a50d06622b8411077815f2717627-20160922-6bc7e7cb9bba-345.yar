rule _20160921_73b5a50d06622b8411077815f2717627_20160922_6bc7e7cb9bba_345 {
  meta:
    description = "datamaliciousorder - from files 20160921_73b5a50d06622b8411077815f2717627.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8a171dec88d707916b1928e49d84c61474fe9b0faf2916e72eadb2b404d04b"
    hash2       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1  = "(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";" ascii
    $s2  = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})()," ascii
    $s3  = "})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s4  = "(function f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){r" ascii
    $s5  = "turn \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6  = "turn \"Yv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OMd\";})(),(" ascii
    $s7  = "(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";" ascii
    $s8  = "0(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";" ascii
    $s9  = " f000(){return \"NYh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s10 = "){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";}" ascii
    $s11 = "n f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s12 = "turn \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"YTp\";})(),(" ascii
    $s13 = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km" ascii
    $s14 = "ion f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s15 = "Gn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s16 = "eturn \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s17 = "n \"Iq\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s18 = "Gn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii
    $s19 = "on f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"" ascii
    $s20 = "\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}