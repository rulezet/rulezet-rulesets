rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4865 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "{return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return" ascii
    $s3 = "(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\"" ascii
    $s4 = "\"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s5 = "unction f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}