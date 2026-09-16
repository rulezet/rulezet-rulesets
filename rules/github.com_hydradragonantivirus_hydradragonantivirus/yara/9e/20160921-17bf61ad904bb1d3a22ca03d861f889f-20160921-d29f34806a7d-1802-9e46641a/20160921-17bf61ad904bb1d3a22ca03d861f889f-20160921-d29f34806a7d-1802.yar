rule _20160921_17bf61ad904bb1d3a22ca03d861f889f_20160921_d29f34806a7d_1802 {
  meta:
    description = "datamaliciousorder - from files 20160921_17bf61ad904bb1d3a22ca03d861f889f.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ad9770f05718e622431ef5405e0a702ec2484ecc5b434b1a634c99b480bc855"
    hash2       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1  = ",(function fuck(){return \"Sx\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){r" ascii
    $s2  = "(){return \"RAi\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s3  = "n \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4  = "on fuck(){return \"Xg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5  = ";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fu" ascii
    $s6  = "){return \"Et\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";}" ascii
    $s7  = "eturn \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s8  = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s9  = ",(function fuck(){return \"Ai\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){r" ascii
    $s10 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"A" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}