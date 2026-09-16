rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_28d059ae521d_4632 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"

  strings:
    $s1 = "tion f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn" ascii
    $s3 = "turn \"Um\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})()," ascii
    $s4 = "urn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s5 = "{return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}