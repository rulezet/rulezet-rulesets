rule sig_20160301_e8fb6cba3c62339540d71000c1811298 {
  meta:
    description = "datamaliciousorder - file 20160301_e8fb6cba3c62339540d71000c1811298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d944c691a2fd79122f4363db515ad68ebd9525b0393e45a9f0a4525e9889962f"

  strings:
    $s1 = "while (visaLinguist[(\"\\u0072e\\u0061\" + \"\\u0064\\u0079\\u0073\\u0074\" + \"\\u0061\\u0074\" + \"e\")] < (3 * 2 * 2 / (2 + 1" ascii
    $s2 = "metaphorIntegral = ((((((([+!+[]])) + \"\" + (([+!+[]])))) * ([!+[] + !+[] + !+[]])) / (22 ^ 55)), this);" fullword ascii
    $s3 = "visaLinguist[(\"\\u0063\\u006c\" + \"i\\u0065nt\", function String.prototype.preservativeCareer() {" fullword ascii
    $s4 = "} catch (productSyndicate) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}