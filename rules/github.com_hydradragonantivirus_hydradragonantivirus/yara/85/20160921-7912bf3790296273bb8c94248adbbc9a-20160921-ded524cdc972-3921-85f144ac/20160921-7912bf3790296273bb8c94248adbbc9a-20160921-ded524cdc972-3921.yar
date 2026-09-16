rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_ded524cdc972_3921 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})" ascii
    $s2 = "(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";}" ascii
    $s3 = "ction f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s4 = "(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";}" ascii
    $s5 = "(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sv\";}" ascii
    $s6 = " \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}