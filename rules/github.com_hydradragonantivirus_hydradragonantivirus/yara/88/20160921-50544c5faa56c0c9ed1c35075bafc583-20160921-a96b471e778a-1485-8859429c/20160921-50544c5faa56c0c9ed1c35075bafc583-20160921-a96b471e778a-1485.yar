rule _20160921_50544c5faa56c0c9ed1c35075bafc583_20160921_a96b471e778a_1485 {
  meta:
    description = "datamaliciousorder - from files 20160921_50544c5faa56c0c9ed1c35075bafc583.js, 20160921_a96b471e778a8101c168e06727d930fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"
    hash2       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"

  strings:
    $s1  = "n fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = " fuck(){return \"RAi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s3  = "on fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s4  = " \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(funct" ascii
    $s5  = "XHj\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s6  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Mw\";}" ascii
    $s7  = "unction fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s8  = "fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"C" ascii
    $s9  = "fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu" ascii
    $s10 = ";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"USf\";})(),(function fuc" ascii
    $s11 = "x\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s12 = "(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(" ascii
    $s13 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}