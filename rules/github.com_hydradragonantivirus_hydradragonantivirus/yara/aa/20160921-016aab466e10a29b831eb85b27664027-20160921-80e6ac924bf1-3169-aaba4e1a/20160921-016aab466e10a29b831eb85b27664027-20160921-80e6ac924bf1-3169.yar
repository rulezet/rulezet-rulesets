rule _20160921_016aab466e10a29b831eb85b27664027_20160921_80e6ac924bf1_3169 {
  meta:
    description = "datamaliciousorder - from files 20160921_016aab466e10a29b831eb85b27664027.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6a541dd7e97eedc43f6bcf89f007176352c81c1d1240a76218e73cf5bb3b171"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1 = "{return \"ZIi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})" ascii
    $s2 = "\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3 = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s4 = "t\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s5 = "{return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\";})(" ascii
    $s6 = "tion f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}