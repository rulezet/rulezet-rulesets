rule _20160921_3e5e21af311d364f73107419b54e74e3_20160921_92203c861b27_2917 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e5e21af311d364f73107419b54e74e3.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"
    hash4       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})()" ascii
    $s2 = "\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function " ascii
    $s3 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s4 = "unction f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = "\"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s6 = "turn \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s7 = "),(function f000(){return \"UEg\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}