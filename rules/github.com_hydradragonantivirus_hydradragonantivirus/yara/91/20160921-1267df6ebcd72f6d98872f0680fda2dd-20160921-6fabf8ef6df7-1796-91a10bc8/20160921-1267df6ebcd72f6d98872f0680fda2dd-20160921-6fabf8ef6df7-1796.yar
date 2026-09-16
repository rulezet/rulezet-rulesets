rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_6fabf8ef6df7_1796 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash3       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash4       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"

  strings:
    $s1  = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"KVh\";})(),(function fuck" ascii
    $s2  = "ction fuck(){return \"YAv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s3  = "k(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s4  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){re" ascii
    $s5  = "IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii
    $s6  = "urn \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"CCb\";})(),(f" ascii
    $s7  = "TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(functio" ascii
    $s8  = "uck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy" ascii
    $s9  = "uck(){return \"ZVi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj" ascii
    $s10 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}