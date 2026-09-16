rule _20160921_9dad243650b7872772e7037b467b5a2e_20160921_d6eab67b6b3c_320 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"

  strings:
    $s1  = "f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s2  = "m\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s3  = "0(){return \"ZIi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";" ascii
    $s4  = "00(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj" ascii
    $s5  = "unction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){ret" ascii
    $s6  = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})" ascii
    $s7  = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function " ascii
    $s8  = "000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\"" ascii
    $s9  = "unction f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s10 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s11 = "{return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(" ascii
    $s12 = "tion f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return" ascii
    $s13 = ",(function f000(){return \"BMj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"KXg\";})(),(function f000(){" ascii
    $s14 = "n \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(fu" ascii
    $s15 = "urn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s16 = "eturn \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})()," ascii
    $s17 = "tion f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s18 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qa\";})(),(funct" ascii
    $s19 = "nction f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s20 = "(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}