rule sig_20160301_a74fa73e2920303e036af04e7f803dc2 {
  meta:
    description = "datamaliciousorder - file 20160301_a74fa73e2920303e036af04e7f803dc2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c93cb585987b48c27a5be58e63eb34a84b0d09253765106bb8ce429b4f559e75"

  strings:
    $s1 = "while (cosmosStimulation[(\"t\" + \"e\\u006e\" + \"\\u0064e\" + \"\\u0072\", \"in\" + \"st\\u0072\\u0075c\" + \"\\u0074\" + \"" ascii
    $s2 = "while (cosmosStimulation[(\"t\" + \"e\\u006e\" + \"\\u0064e\" + \"\\u0072\", \"in\" + \"st\\u0072\\u0075c\" + \"\\u0074\" + \"" ascii
    $s3 = "rationalCabin[(\"u\" + \"n\\u0069\" + \"v\" + \"\\u0065\\u0072se\", function String.prototype.effectSpecification() {" fullword ascii
    $s4 = "massBarrack = (((1 ^ 0) & (1)), this);" fullword ascii
    $s5 = "} catch (transformUniversal) {};" fullword ascii

  condition:
    uint16(0) == 0x616d and
    all of them
}