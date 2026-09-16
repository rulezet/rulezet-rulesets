rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_5f0fd6cffcc7_4611 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_702e8529103b960a902ddb030da0de45.js, 20160921_a1cbb43a1e22a4b1fd63ee1a724173eb.js, 20160921_cae1392fd0c6da8c370b46e3e8040401.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_da7f7f057c35b886425ec822f654da90.js, 20160921_e83251070761df6a7fe56a790f4a7a43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash3       = "cf8ba9fdbe4ef225cb892f7294538710b1dd7e8bc4e280897680c51e03816d1c"
    hash4       = "4154e4928eccd35fa0d42dbefe4a742700d77124216f8b5756b8ef63634071d3"
    hash5       = "f67c8d099609c97880a9ea12beb3c83faaf2411bf12032595ad5baa45d985a04"
    hash6       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash7       = "b6935463e925cb13fc2413b3d7559cf8e9f5072c15dc73075977046a3e27e417"
    hash8       = "0ca0db55a551923b328ba28035ed857a5c51dfd4c6e1060bd34ab4bc3d27b75f"

  strings:
    $s1 = "turn \"Iq\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(" ascii
    $s2 = " f000(){return \"MJq\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"W" ascii
    $s3 = "ction f000(){return \"Mc\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKp\";})(),(function f000(){return" ascii
    $s4 = "\"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"UEg\";})(),(func" ascii
    $s5 = ";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lo\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}