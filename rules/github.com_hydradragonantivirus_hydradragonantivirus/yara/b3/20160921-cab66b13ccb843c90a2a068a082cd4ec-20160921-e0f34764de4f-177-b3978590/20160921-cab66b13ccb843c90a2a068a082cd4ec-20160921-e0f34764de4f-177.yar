rule _20160921_cab66b13ccb843c90a2a068a082cd4ec_20160921_e0f34764de4f_177 {
  meta:
    description = "datamaliciousorder - from files 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1  = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"SEo\";})(),(function f" ascii
    $s2  = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})()," ascii
    $s3  = "00(){return \"KDh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn" ascii
    $s4  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wy\";})()," ascii
    $s5  = " \"Yz\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s6  = "Ij\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function" ascii
    $s7  = "tion f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s8  = "{return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";}" ascii
    $s9  = ";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s10 = "eturn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(" ascii
    $s11 = "f000(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DI" ascii
    $s12 = "ction f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s13 = "eturn \"MMz\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"MDb\";})()" ascii
    $s14 = " f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"" ascii
    $s15 = "on f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Z" ascii
    $s16 = "urn \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(" ascii
    $s17 = "tion f000(){return \"Qj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s18 = "0(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\"" ascii
    $s19 = "){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})" ascii
    $s20 = "ction f000(){return \"BMj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}