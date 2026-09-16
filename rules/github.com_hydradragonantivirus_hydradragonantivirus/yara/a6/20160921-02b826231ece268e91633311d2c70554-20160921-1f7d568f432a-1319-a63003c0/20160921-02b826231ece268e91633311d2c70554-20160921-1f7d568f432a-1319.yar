rule _20160921_02b826231ece268e91633311d2c70554_20160921_1f7d568f432a_1319 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"

  strings:
    $s1  = "(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){re" ascii
    $s2  = ",(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s3  = "urn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s4  = "\"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";})(),(functi" ascii
    $s5  = "n f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Lo" ascii
    $s6  = "MJq\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s7  = "0(){return \"SGs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp" ascii
    $s8  = "urn \"Nv\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s9  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(f" ascii
    $s10 = "unction f000(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s11 = "),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Mc\";})(),(function f000(){r" ascii
    $s12 = "ction f000(){return \"IPu\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){return" ascii
    $s13 = "m\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s14 = "rn \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s15 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}