rule _20160921_26653257e0da59c861fc658d3bccdafd_20160921_6fabf8ef6df7_4756 {
  meta:
    description = "datamaliciousorder - from files 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash3       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"

  strings:
    $s1 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuc" ascii
    $s2 = "(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s3 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s4 = "Qr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s5 = "uck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LL" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}