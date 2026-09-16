rule _20160921_25c11e2eab44b5e0380e0bd805a72790_20160921_61ffae07802b_4747 {
  meta:
    description = "datamaliciousorder - from files 20160921_25c11e2eab44b5e0380e0bd805a72790.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_8d22ed47876b303a1415a88483556238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912d9aec3079fb6a2e4f83d3826286707a52a653de6ec6eede9711d5b416a790"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"

  strings:
    $s1 = "(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";}" ascii
    $s2 = "n \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(fun" ascii
    $s3 = "00(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\"" ascii
    $s4 = "ction f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s5 = "unction f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}