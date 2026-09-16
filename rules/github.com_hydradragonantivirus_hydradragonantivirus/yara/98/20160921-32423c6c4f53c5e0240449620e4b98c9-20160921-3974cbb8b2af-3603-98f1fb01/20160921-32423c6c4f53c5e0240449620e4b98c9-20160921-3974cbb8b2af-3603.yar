rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_3603 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "n f000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"" ascii
    $s2 = "(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s3 = ")(),(function f000(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(function f000" ascii
    $s4 = "rn \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"KXg\";})(),(fu" ascii
    $s5 = "){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(" ascii
    $s6 = "(function f000(){return \"EZu\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}