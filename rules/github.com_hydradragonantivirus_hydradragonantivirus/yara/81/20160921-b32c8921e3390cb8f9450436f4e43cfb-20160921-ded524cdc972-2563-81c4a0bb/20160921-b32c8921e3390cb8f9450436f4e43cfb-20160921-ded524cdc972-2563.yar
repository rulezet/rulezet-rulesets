rule _20160921_b32c8921e3390cb8f9450436f4e43cfb_20160921_ded524cdc972_2563 {
  meta:
    description = "datamaliciousorder - from files 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "n f000(){return \"Go\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"G" ascii
    $s2 = "eturn \"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"RVb\";})(" ascii
    $s3 = "f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Wb" ascii
    $s4 = ";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NBs\";})(),(function f0" ascii
    $s5 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s6 = "urn \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})()," ascii
    $s7 = "{return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(" ascii
    $s8 = " \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"XTn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}