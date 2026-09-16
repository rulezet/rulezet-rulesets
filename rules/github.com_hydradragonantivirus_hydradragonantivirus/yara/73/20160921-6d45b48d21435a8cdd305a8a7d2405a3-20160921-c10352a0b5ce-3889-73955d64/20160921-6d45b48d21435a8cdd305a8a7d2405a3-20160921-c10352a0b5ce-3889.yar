rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_c10352a0b5ce_3889 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "turn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})()," ascii
    $s2 = "(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";" ascii
    $s3 = "000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw" ascii
    $s4 = "(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";}" ascii
    $s5 = "})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s6 = "n f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}