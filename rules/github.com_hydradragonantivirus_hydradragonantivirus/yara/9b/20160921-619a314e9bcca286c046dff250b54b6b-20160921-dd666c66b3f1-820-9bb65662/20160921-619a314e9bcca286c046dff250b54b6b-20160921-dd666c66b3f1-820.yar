rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_dd666c66b3f1_820 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1  = ")(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Qj\";})(),(function f000" ascii
    $s2  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(fun" ascii
    $s3  = "(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Zj\";})" ascii
    $s4  = "(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";}" ascii
    $s5  = "n f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s6  = "(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){" ascii
    $s7  = "unction f000(){return \"Vu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s8  = "n \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s9  = "f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz" ascii
    $s10 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wy\";})(),(function " ascii
    $s11 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})(" ascii
    $s12 = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){retu" ascii
    $s13 = "nction f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MBb\";})(),(function f000(){ret" ascii
    $s14 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retur" ascii
    $s15 = "nction f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s16 = " \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(funct" ascii
    $s17 = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"" ascii
    $s18 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DYx\";})()" ascii
    $s19 = "0(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s20 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}