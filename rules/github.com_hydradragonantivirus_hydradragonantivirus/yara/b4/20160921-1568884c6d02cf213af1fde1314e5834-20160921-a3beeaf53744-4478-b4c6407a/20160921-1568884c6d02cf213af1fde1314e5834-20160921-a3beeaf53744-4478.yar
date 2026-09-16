rule _20160921_1568884c6d02cf213af1fde1314e5834_20160921_a3beeaf53744_4478 {
  meta:
    description = "datamaliciousorder - from files 20160921_1568884c6d02cf213af1fde1314e5834.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a403e048902def05111493a952d740537d8afbb402b2336c8de1d8a2d6c38940"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"
    hash3       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"

  strings:
    $s1 = "(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})" ascii
    $s2 = "return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(" ascii
    $s3 = "n f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"G" ascii
    $s4 = "n \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s5 = "return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}