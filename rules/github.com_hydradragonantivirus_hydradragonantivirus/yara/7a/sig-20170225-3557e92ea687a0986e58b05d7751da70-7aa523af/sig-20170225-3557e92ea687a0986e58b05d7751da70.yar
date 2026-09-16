rule sig_20170225_3557e92ea687a0986e58b05d7751da70 {
  meta:
    description = "datamaliciousorder - file 20170225_3557e92ea687a0986e58b05d7751da70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b929ff05ce8791e5a58d7c222270d7849ef1c73ff435e691fef14b894e17f4a7"

  strings:
    $s1 = "var x = new Array(\"mvtrading.net\", \"fitnessdigezt.com\", \"richmondyachtbasin.com\", \"residences.springcreekranch.org\", \"c" ascii
    $s2 = "var x = new Array(\"mvtrading.net\", \"fitnessdigezt.com\", \"richmondyachtbasin.com\", \"residences.springcreekranch.org\", \"c" ascii
    $s3 = "e.open(\"G\"+\"E\"+\"T\", t4 + \":\"+ter+ter+x[i]+\"/c\"+\"o\"+\"unter/?\"+m, false);" fullword ascii
    $s4 = "return new ActiveXObject(g2);" fullword ascii
    $s5 = "var vDJmB = function(){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}