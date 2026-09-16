rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_8b9d3c425718_1698 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_8b9d3c425718975422f8fe0d71119686.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "523032dc97c061d21e22a215d1568aa470cd8d5f46ddb3bae63dafcde8db3687"
    hash3       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1  = "(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})(),(function fuck" ascii
    $s2  = "urn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(f" ascii
    $s3  = "eturn \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s4  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"S" ascii
    $s5  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";" ascii
    $s6  = "fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"A" ascii
    $s7  = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function" ascii
    $s8  = "GWo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s9  = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Fv\";})()" ascii
    $s10 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Mw\";})(),(function " ascii
    $s11 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}