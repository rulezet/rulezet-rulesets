rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_f11c35e31593_5549 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "return \"Wh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})()," ascii
    $s2 = "turn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"QDg\";})()," ascii
    $s3 = "function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){r" ascii
    $s4 = "n f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KX" ascii
    $s5 = "00(){return \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}