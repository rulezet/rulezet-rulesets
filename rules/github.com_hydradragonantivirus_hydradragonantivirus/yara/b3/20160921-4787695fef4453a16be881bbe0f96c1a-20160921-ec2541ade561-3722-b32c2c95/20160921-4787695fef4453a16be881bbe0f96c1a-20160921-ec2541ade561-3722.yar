rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_ec2541ade561_3722 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_ec2541ade561a4750092fda52be6f269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "1db7ed5a240fde30e4fca12eca866b9b96b56836ae50ea4c0fcf2d28b08be3b5"

  strings:
    $s1 = "(){return \"PTi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DAp\"" ascii
    $s2 = "ion f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RLk\";})(),(function f000(){return" ascii
    $s3 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f00" ascii
    $s4 = "{return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(" ascii
    $s5 = "function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){r" ascii
    $s6 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}