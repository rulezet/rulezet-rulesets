rule sig_20160301_6d5b3c9798f6e012d02c92bbcf38e756 {
  meta:
    description = "datamaliciousorder - file 20160301_6d5b3c9798f6e012d02c92bbcf38e756.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e89fe76ee4867383fca138a0114fb6360344939baa9291a1158d9f04855bae3"

  strings:
    $s1 = "while(actionPresent[(\"\\u0072ea\\u0064\\u0079s\" + \"t\\u0061t\\u0065\")] < ((33 - 7) - (Math.pow(30, 2) - 878))) {" fullword ascii
    $s2 = "originalApparatus = (((19, 156, 154, 244), (6 - 5)), this);" fullword ascii
    $s3 = "grammarExamine = originalApparatus[(\"m\\u0069n\\u0075t\" + \"e\", \"m\" + \"\\u006fme\" + \"n\\u0074\\u0075m\", \"\\u0063\\u006" ascii
    $s4 = "4\\u0065\" + \"nt\", function String.prototype.stimulationRelaxation() {" fullword ascii
    $s5 = "} catch(passPhotograph) {};" fullword ascii

  condition:
    uint16(0) == 0x726f and
    all of them
}