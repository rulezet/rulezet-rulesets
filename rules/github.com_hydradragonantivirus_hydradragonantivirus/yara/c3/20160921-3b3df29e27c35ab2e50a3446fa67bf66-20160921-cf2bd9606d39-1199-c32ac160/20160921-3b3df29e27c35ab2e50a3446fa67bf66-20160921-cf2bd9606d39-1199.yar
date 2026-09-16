rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_cf2bd9606d39_1199 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1  = "{return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})()" ascii
    $s2  = "ion f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return " ascii
    $s3  = "n f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s4  = "(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s5  = "000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn" ascii
    $s6  = "KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s7  = "\"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s8  = "turn \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s9  = "on f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return " ascii
    $s10 = "rn \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(f" ascii
    $s11 = "n\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s12 = "urn \"GGn\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})()," ascii
    $s13 = "return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})" ascii
    $s14 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"" ascii
    $s15 = "on f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s16 = "f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}