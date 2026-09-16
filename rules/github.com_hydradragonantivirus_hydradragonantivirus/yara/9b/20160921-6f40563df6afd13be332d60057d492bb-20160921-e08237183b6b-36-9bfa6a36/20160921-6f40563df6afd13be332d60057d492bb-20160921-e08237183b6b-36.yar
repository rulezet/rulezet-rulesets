rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_e08237183b6b_36 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1  = "GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wy\";})(),(functi" ascii
    $s2  = "(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(" ascii
    $s3  = "\"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BQb\";})(),(func" ascii
    $s4  = "(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";" ascii
    $s5  = "ction f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s6  = "{return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qa\";})" ascii
    $s7  = " f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"G" ascii
    $s8  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(),(func" ascii
    $s9  = "000(){return \"Qj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s10 = "{return \"Qz\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii
    $s11 = "a\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s12 = "(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000()" ascii
    $s13 = "urn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s14 = " \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(funct" ascii
    $s15 = "unction f000(){return \"ZIi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s16 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZGq\";})" ascii
    $s17 = "f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn" ascii
    $s18 = "){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(" ascii
    $s19 = "return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(" ascii
    $s20 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DYx\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}