rule sig_20160301_d569946ca551987ebb04b5a84f11d012 {
  meta:
    description = "datamaliciousorder - file 20160301_d569946ca551987ebb04b5a84f11d012.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1948723696e76a85d6e8e0cef37087d25fa21f423ee88d678a3d877450b0541"

  strings:
    $s1 = "while(statisticalTheorem[(\"r\\u0065a\\u0064\\u0079\\u0073\" + \"\\u0074\\u0061t\" + \"e\")] < (Math.pow((15), (1 * 2)) - 13 * 1" ascii
    $s2 = "refrigeratorInterpretation = ((0 + 1), this);" fullword ascii
    $s3 = "armyBoxing = vitaminElastic[(\"m\\u0065\\u006d\\u0062\\u0072\" + \"\\u0061\\u006e\" + \"e\", \"E\\u0078\\u0070\\u0061\" + \"\\u0" ascii
    $s4 = "\"\\u0065\", \"\\u0063o\\u0070y\", function String.prototype.interpretAlcohol() {" fullword ascii
    $s5 = "} catch(veteranReport) {};" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}