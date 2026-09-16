rule _20160921_f7b964e1d5b6c5c4999da8838c5d62ca_20160921_fd5fc0674575_4082 {
  meta:
    description = "datamaliciousorder - from files 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";" ascii
    $s2 = "unction f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s3 = "rn \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(fun" ascii
    $s4 = "\"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s5 = "\"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s6 = "n\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}