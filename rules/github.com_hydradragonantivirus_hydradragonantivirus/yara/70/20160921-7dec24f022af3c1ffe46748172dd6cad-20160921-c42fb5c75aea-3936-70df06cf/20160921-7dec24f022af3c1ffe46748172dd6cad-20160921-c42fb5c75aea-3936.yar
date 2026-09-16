rule _20160921_7dec24f022af3c1ffe46748172dd6cad_20160921_c42fb5c75aea_3936 {
  meta:
    description = "datamaliciousorder - from files 20160921_7dec24f022af3c1ffe46748172dd6cad.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402e919998fdba69cb3992879db4f947916245c38915db643643952fa450e947"
    hash2       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash3       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"

  strings:
    $s1 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Fv\"" ascii
    $s2 = "){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3 = "eturn \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Jh\";})(),(" ascii
    $s4 = "),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Jo\";})(),(function fuck()" ascii
    $s5 = "IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(functi" ascii
    $s6 = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}