rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_14f99bec2c2e_4305 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash3       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"

  strings:
    $s1 = "{return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";}" ascii
    $s2 = "\"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s3 = "urn \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s4 = "0(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";" ascii
    $s5 = "(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}