rule sig_20160301_c2c6a59c26953bac18f42b430a4f20a3 {
  meta:
    description = "datamaliciousorder - file 20160301_c2c6a59c26953bac18f42b430a4f20a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e182dad9acfd2ccd8133189848b9dfb742be3acb78b63d7382dcbb20fdb32a9"

  strings:
    $s1 = "   infectionAxiom[(\"o\\u0070\\u0065\" + \"\\u0072a\", function String.prototype.recipeCommand() {" fullword ascii
    $s2 = "controlEffect = (((49 - 48) * 1), this);" fullword ascii
    $s3 = "while(officialCamera[(\"r\\u0065\\u0061\\u0064ys\" + \"t\\u0061\" + \"t\\u0065\")] < (Math.pow(3 * 3, (0 | 2)) - (77))) {" fullword ascii
    $s4 = "} catch(actChaos) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}