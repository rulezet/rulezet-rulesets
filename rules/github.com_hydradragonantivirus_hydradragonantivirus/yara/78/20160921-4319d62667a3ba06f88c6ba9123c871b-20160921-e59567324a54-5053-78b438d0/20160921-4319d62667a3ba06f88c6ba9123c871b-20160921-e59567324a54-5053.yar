rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_e59567324a54_5053 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"
    hash3       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1 = "ion f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"" ascii
    $s2 = "unction f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii
    $s3 = "return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(" ascii
    $s4 = "n \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}