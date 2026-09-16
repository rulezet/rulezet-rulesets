rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_80e6ac924bf1_5052 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash3       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1 = "f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s2 = "(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s3 = "\"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(funct" ascii
    $s4 = "\"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s5 = "(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}