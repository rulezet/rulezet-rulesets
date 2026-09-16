rule _20160921_28d059ae521dbabe2afdc3bfd464938c_20160922_433c067ed379_583 {
  meta:
    description = "datamaliciousorder - from files 20160921_28d059ae521dbabe2afdc3bfd464938c.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1  = "0(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";" ascii
    $s2  = "ction f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii
    $s3  = "00(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn" ascii
    $s4  = "\"Yv\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5  = "0(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn" ascii
    $s6  = " f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Lp" ascii
    $s7  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s8  = "return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(" ascii
    $s9  = "(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){" ascii
    $s10 = " f000(){return \"MJq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s11 = "ion f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s12 = " f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s13 = "rn \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s14 = "(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(" ascii
    $s15 = "ction f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return" ascii
    $s16 = "000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\"" ascii
    $s17 = "\"RPt\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"PTs\";})(),(fun" ascii
    $s18 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return " ascii
    $s19 = "urn \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(fu" ascii
    $s20 = "(),(function f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}