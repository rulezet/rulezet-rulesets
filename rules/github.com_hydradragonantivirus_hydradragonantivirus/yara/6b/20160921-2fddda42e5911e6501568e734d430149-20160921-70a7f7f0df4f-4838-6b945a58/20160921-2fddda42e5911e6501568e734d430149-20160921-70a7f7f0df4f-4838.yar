rule _20160921_2fddda42e5911e6501568e734d430149_20160921_70a7f7f0df4f_4838 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"

  strings:
    $s1 = "(){return \"YTp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = "(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s3 = "n \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(fu" ascii
    $s4 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(functi" ascii
    $s5 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}