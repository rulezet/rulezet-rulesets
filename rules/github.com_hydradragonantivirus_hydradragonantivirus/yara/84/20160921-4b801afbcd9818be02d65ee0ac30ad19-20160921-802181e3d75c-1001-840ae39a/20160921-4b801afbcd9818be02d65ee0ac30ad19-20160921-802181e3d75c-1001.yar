rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_802181e3d75c_1001 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1  = "function f000(){return \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s2  = "turn \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s3  = "n f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"W" ascii
    $s4  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function " ascii
    $s5  = ")(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s6  = "return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})()" ascii
    $s7  = "eturn \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})()," ascii
    $s8  = "ction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s9  = " f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"" ascii
    $s10 = "000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s11 = ";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f0" ascii
    $s12 = "eturn \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})()," ascii
    $s13 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(fu" ascii
    $s14 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s15 = "\"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(functi" ascii
    $s16 = "on f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s17 = "(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s18 = "eturn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})()," ascii
    $s19 = "tion f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}