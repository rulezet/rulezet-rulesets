rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_e1bc53e337e2_5425 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "})(),(function f000(){return \"Um\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii
    $s2 = ",(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii
    $s3 = "ction f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){retur" ascii
    $s4 = "n \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(f" ascii
    $s5 = "f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJ" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}