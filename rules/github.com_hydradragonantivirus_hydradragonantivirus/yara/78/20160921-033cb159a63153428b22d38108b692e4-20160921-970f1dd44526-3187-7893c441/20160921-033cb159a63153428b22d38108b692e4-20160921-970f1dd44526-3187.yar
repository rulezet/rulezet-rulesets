rule _20160921_033cb159a63153428b22d38108b692e4_20160921_970f1dd44526_3187 {
  meta:
    description = "datamaliciousorder - from files 20160921_033cb159a63153428b22d38108b692e4.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2c7637ff56cbf278f1a457ae1833df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d370303fc83ddc3470e00cb54841641f9f338c2f025096e84d40782778041a8b"
    hash2       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash3       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash4       = "a19789bb6f28d27bc82c039f4db69fb5cc4c189a7a47cddfffcdc6eace37a408"

  strings:
    $s1 = "urn \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s2 = "){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";}" ascii
    $s3 = "tion f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s4 = "eturn \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})()" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})" ascii
    $s6 = ")(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}