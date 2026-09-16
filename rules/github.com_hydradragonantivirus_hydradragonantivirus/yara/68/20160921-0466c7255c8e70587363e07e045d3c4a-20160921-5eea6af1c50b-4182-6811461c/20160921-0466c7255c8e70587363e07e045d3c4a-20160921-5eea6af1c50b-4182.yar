rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_5eea6af1c50b_4182 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_5eea6af1c50b807f547cb710eb413110.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"

  strings:
    $s1 = ";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f" ascii
    $s2 = "rn \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s3 = "ion f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s4 = "return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(" ascii
    $s5 = "00(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}