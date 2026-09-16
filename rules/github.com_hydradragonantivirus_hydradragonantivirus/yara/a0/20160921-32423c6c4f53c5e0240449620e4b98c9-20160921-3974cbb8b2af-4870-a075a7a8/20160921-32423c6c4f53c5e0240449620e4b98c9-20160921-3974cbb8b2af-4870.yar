rule _20160921_32423c6c4f53c5e0240449620e4b98c9_20160921_3974cbb8b2af_4870 {
  meta:
    description = "datamaliciousorder - from files 20160921_32423c6c4f53c5e0240449620e4b98c9.js, 20160921_3974cbb8b2af1f98b68ab31621da93d9.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_c6543124cf4219fa4e40c0a11c36d211.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160922_0d54e6d044b32b4a5cb86183b32db7ff.js, 20160922_9b3b116ccafe79961f3e5b8baaf2ade1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1627aa0e729ffe8aba0e7faa8a6286c25a744600e193b72dbc3254fcc98a6003"
    hash2       = "707fba854060aa6294a0cf0c11b8eed992c56785375920bc41b7e95f514ab760"
    hash3       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"
    hash4       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash5       = "2e6e6772ef9133726c2b17ebda7c01433c0b60252b2e9446e3c8a2e6595d981c"
    hash6       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash7       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash8       = "bdad94d3c22138ff9e5f70b983cbfbfaee137dc676cd8889f048ac4db0e3e1de"
    hash9       = "3e53e6ba6e3163cbf17f110b2b7e3a79966fc578ec4ae1ed2de13f0fac0de834"

  strings:
    $s1 = "rn \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(fu" ascii
    $s2 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(func" ascii
    $s3 = "000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv" ascii
    $s4 = "ion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return " ascii
    $s5 = ")(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}