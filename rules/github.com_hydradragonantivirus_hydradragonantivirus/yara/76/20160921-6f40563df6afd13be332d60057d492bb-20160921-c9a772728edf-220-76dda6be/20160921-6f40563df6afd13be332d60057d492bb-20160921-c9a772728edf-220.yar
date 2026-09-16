rule _20160921_6f40563df6afd13be332d60057d492bb_20160921_c9a772728edf_220 {
  meta:
    description = "datamaliciousorder - from files 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash2       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash3       = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"

  strings:
    $s1  = "(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){" ascii
    $s2  = "return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s3  = "nction f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s4  = "00(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";" ascii
    $s5  = "on f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"M" ascii
    $s6  = "urn \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s7  = "turn \"Oh\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(f" ascii
    $s8  = " \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s9  = ")(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s10 = "000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sv\"" ascii
    $s11 = "eturn \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})()," ascii
    $s12 = "ction f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){retu" ascii
    $s13 = "),(function f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(" ascii
    $s14 = ")(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s15 = " f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Z" ascii
    $s16 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s17 = "unction f000(){return \"Mu\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s18 = "n f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Q" ascii
    $s19 = "Ux\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NBs\";})(),(functio" ascii
    $s20 = "on f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}