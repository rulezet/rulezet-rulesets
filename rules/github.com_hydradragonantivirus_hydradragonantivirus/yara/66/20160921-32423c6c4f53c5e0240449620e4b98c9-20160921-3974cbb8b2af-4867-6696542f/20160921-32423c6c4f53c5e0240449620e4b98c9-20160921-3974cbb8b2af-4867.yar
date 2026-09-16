rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4867 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_cbfbdc544b309301bc71d300d7726545.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"
    hash4       = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1 = "n f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s3 = "eturn \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})()," ascii
    $s4 = "){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";}" ascii
    $s5 = "0(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"XTn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}