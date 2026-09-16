rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_1c0508ced9fa_136 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_c10352a0b5ce476f023184a502920234.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js, 20160921_e1835bc92c4604db194bc49df621cade.js, 20160921_f5decbca2e5a35bbb5c42091c1b0c30e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash3       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash4       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash5       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash6       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash7       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash8       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash9       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"
    hash10      = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"
    hash11      = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"
    hash12      = "5fe03908bd7d860f1260a3264b2e10de3115d24242a095cf4c0b73e7934ce89e"

  strings:
    $s1  = "000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"RVb" ascii
    $s2  = "unction f000(){return \"Oh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s3  = "eturn \"Br\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yz\";})(),(" ascii
    $s4  = "0(){return \"DAp\";})(),(function f000(){return \"MOc\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii
    $s5  = "unction f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s6  = "unction f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s7  = "(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s8  = "return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(" ascii
    $s9  = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Br\";})()" ascii
    $s10 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s11 = "n \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s12 = "\"Tb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s13 = "\"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"YTp\";})(),(func" ascii
    $s14 = "unction f000(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Rh\";})(),(function f000(){retur" ascii
    $s15 = "(){return \"ZIi\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";}" ascii
    $s16 = "\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function " ascii
    $s17 = "(){return \"Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"UEg\";" ascii
    $s18 = "(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s19 = ";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f00" ascii
    $s20 = "n \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}