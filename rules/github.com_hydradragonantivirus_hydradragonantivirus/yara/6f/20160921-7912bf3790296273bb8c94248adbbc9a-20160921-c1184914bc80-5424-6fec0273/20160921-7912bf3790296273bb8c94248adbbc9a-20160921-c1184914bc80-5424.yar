rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_c1184914bc80_5424 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_c1184914bc801e9725b7f52a13eaa885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "b978f77ee1e2384ffdbb55f48f7d8fb0a9b642fc4b2f38d86c68e4f6357d5153"

  strings:
    $s1 = "00(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"DNa" ascii
    $s2 = "0(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s3 = ")(),(function f000(){return \"NYh\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"OMd\";})(),(function f00" ascii
    $s4 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f" ascii
    $s5 = " \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}