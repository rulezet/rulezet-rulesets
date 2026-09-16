rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_8d22ed47876b_1886 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash3       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1  = "ction f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s2  = ";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f0" ascii
    $s3  = "h\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function " ascii
    $s4  = " f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Z" ascii
    $s5  = "return \"Vj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})()" ascii
    $s6  = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s7  = "eturn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(" ascii
    $s8  = "function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s9  = "eturn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})()," ascii
    $s10 = "(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}