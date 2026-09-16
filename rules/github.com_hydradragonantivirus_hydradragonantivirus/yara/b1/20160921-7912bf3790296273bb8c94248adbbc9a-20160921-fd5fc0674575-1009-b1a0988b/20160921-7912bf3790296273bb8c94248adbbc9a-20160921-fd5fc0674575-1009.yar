rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_fd5fc0674575_1009 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retu" ascii
    $s2  = "k\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function " ascii
    $s3  = "nction f000(){return \"MMz\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){retu" ascii
    $s4  = "f000(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GG" ascii
    $s5  = "return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(" ascii
    $s6  = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s7  = "{return \"HJm\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";}" ascii
    $s8  = "tion f000(){return \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"BQb\";})(),(function f000(){retur" ascii
    $s9  = "\"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(funct" ascii
    $s10 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f0" ascii
    $s11 = "f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s12 = "})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Kw\";})(),(function f000(" ascii
    $s13 = "00(){return \"SEo\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"MDb" ascii
    $s14 = "rn \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"IAa\";})(),(f" ascii
    $s15 = "(){return \"Um\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";}" ascii
    $s16 = "ion f000(){return \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s17 = " \"Rh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(fun" ascii
    $s18 = "ction f000(){return \"QDg\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii
    $s19 = "function f000(){return \"MMz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}