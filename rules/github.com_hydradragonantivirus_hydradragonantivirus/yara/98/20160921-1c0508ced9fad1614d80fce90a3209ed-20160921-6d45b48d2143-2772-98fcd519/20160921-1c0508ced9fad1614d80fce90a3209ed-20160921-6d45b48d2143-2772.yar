rule _20160921_1c0508ced9fad1614d80fce90a3209ed_20160921_6d45b48d2143_2772 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c0508ced9fad1614d80fce90a3209ed.js, 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e27406e32c891781b5403c718c4f32d67f6580cf6f952a30d0c6452ab9775a4c"
    hash2       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"

  strings:
    $s1 = ",(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s2 = "){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";}" ascii
    $s3 = "urn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s4 = "\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s5 = "rn \"Yi\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fu" ascii
    $s6 = "ction f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){retu" ascii
    $s7 = "ion f000(){return \"Rh\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}