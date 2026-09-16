rule sig_20160301_40d3b3d4280388c4564b5e2d71814c4a {
  meta:
    description = "datamaliciousorder - file 20160301_40d3b3d4280388c4564b5e2d71814c4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fc7d550f99b6d394b6b93f1dba8e1adc515edf32fe7762e0e976f3a4d685266"

  strings:
    $s1 = "} catch (infectionRespectable) {};" fullword ascii
    $s2 = "while (examinationTransform[(\"\\u0076acan\" + \"\\u0063\" + \"\\u0079\", \"\\u0061u\\u0063\\u0074i\" + \"\\u006f\" + \"\\u006e" ascii
    $s3 = "5\\u004f\" + \"\\u0062\\u006ae\" + \"ct\")]((\"\\u0061n\" + \"\\u0061l\\u006f\" + \"g\\u0079\", function String.prototype.balanc" ascii
    $s4 = "while (examinationTransform[(\"\\u0076acan\" + \"\\u0063\" + \"\\u0079\", \"\\u0061u\\u0063\\u0074i\" + \"\\u006f\" + \"\\u006e" ascii
    $s5 = "deltaPerson = (((360 / 20) / (30 & 19)), this);" fullword ascii
    $s6 = "rationalPhotograph = deltaPerson[(\"s\\u0070\" + \"o\\u006es\" + \"o\\u0072\", \"\\u0072\" + \"a\\u0063\" + \"\\u0065\", \"\\u00" ascii

  condition:
    uint16(0) == 0x6564 and
    all of them
}