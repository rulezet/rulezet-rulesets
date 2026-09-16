rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_d53637406b06_178 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash3       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"
    hash4       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash5       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = "\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function" ascii
    $s2  = "tion f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return" ascii
    $s3  = "0(){return \"Um\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";" ascii
    $s4  = ",(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){" ascii
    $s5  = "eturn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"TKp\";})(" ascii
    $s6  = "0(){return \"DAp\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Wb\";" ascii
    $s7  = "\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f" ascii
    $s8  = "),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(" ascii
    $s9  = "on f000(){return \"Lp\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s10 = "nction f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){retu" ascii
    $s11 = "),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(" ascii
    $s12 = "rn \"SEo\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s13 = "urn \"Go\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s14 = "return \"DNa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s15 = "on f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"B" ascii
    $s16 = "unction f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s17 = "rn \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s18 = "f000(){return \"Lp\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn" ascii
    $s19 = " \"DYs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s20 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SEo\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}