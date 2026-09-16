rule _20160921_5d6863feab411af8217516a1b111aa40_20160921_b2867778b87a_421 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1  = "rn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(" ascii
    $s2  = "return \"IAa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s3  = "(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s4  = "})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"KXg\";})(),(function f0" ascii
    $s5  = "0(){return \"Br\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Br\";})" ascii
    $s6  = "})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s7  = "b\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s8  = "ZFe\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s9  = "\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt\";})(),(function " ascii
    $s10 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"" ascii
    $s11 = "(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wb\";})(),(function f000(){r" ascii
    $s12 = "n \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(fu" ascii
    $s13 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Sq" ascii
    $s14 = "urn \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Oe\";})(),(fu" ascii
    $s15 = "nction f000(){return \"DAp\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s16 = "})(),(function f000(){return \"MMz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s17 = "\"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(funct" ascii
    $s18 = "(function f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii
    $s19 = "IPu\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s20 = "function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Mc\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}