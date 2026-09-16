rule _20160922_433c067ed37935e72b4e47664c370c44_20160922_b640840d7ced_26 {
  meta:
    description = "datamaliciousorder - from files 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash2       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "l\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(functio" ascii
    $s2  = " f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt" ascii
    $s3  = "0(){return \"Nv\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";" ascii
    $s4  = "return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s5  = "turn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Yi\";})()," ascii
    $s6  = " \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(func" ascii
    $s7  = "(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"PTs\";}" ascii
    $s8  = "(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){r" ascii
    $s9  = "eturn \"Vu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Ml\";})(),(" ascii
    $s10 = "){return \"Qj\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(" ascii
    $s11 = "\"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s12 = "){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";}" ascii
    $s13 = "unction f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"SEo\";})(),(function f000(){re" ascii
    $s14 = "n f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"D" ascii
    $s15 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s16 = "ion f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s17 = " \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(fun" ascii
    $s18 = "w\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s19 = " \"QDg\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s20 = "urn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}