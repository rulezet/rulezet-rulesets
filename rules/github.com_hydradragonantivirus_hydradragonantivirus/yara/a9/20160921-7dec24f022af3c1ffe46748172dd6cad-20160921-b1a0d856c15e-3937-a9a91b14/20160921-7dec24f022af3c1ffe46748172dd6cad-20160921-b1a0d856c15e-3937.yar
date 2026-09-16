rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_b1a0d856c15e_3937 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_b1a0d856c15e8cb36e6ba699332db942.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "88dbe0c95aef9105f735a6441467700856e7377cc24ac1dbd7d9bcd256b0aa29"
    hash3       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"
    hash4       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "uck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu" ascii
    $s2 = " \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(functi" ascii
    $s3 = "on fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s4 = "\"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(func" ascii
    $s5 = "unction fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){retur" ascii
    $s6 = "){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}