rule _20160921_073b3e31779f349650fc6977a0add94b_20160921_0cff9f091048_893 {
  meta:
    description = "datamaliciousorder - from files 20160921_073b3e31779f349650fc6977a0add94b.js, 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash2       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1  = "urn \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s2  = "(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s3  = "(),(function f000(){return \"KDh\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"MDb\";})(),(function f000" ascii
    $s4  = "return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5  = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function" ascii
    $s6  = "(),(function f000(){return \"DAp\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(" ascii
    $s7  = "ion f000(){return \"DYs\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s8  = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s9  = "on f000(){return \"Um\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"" ascii
    $s10 = "})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MJq\";})(),(function f00" ascii
    $s11 = "MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(funct" ascii
    $s12 = "unction f000(){return \"MJq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){ret" ascii
    $s13 = "\"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Oh\";})(),(funct" ascii
    $s14 = "f000(){return \"MMz\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb" ascii
    $s15 = "(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){r" ascii
    $s16 = "})(),(function f000(){return \"MMz\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qj\";})(),(function f00" ascii
    $s17 = "a\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s18 = "rn \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qj\";})(),(fu" ascii
    $s19 = "000(){return \"Wb\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo" ascii
    $s20 = "{return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}