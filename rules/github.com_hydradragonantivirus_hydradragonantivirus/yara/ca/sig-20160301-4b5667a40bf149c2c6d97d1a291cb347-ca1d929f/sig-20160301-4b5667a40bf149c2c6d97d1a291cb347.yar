rule sig_20160301_4b5667a40bf149c2c6d97d1a291cb347 {
  meta:
    description = "datamaliciousorder - file 20160301_4b5667a40bf149c2c6d97d1a291cb347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "152510359caa0aa8ad5b3f5799ad6ff11e34a8044dd65e1176c2a3424699c28d"

  strings:
    $s1 = "revisionProcedure = distanceMajor[(\"statuette\", \"computer\", \"variation\", \"information\", \"ExpandEnvironmentStrings\")]((" ascii
    $s2 = "while (absoluteAnalogy[(\"nose\", \"readystate\")] < ((3 + 1) ^ (([+[]])))) {" fullword ascii
    $s3 = "revisionProcedure = distanceMajor[(\"statuette\", \"computer\", \"variation\", \"information\", \"ExpandEnvironmentStrings\")]((" ascii
    $s4 = "offsetIndustrial = giganticManifest[(\"cycle\", \"inspection\", \"cocoon\", \"WScript\")][(\"portal\", \"text\", \"industrializa" ascii
    $s5 = "giganticManifest = (((160 | 33) | (144 - 95)), this);" fullword ascii
    $s6 = "offsetIndustrial[(\"plan\", \"trilogy\", \"write\")](absoluteAnalogy[(\"phrase\", \"transportation\", function String.prototype." ascii
    $s7 = "offsetIndustrial[(\"plan\", \"trilogy\", \"write\")](absoluteAnalogy[(\"phrase\", \"transportation\", function String.prototype." ascii
    $s8 = "} catch (regulateMemoirs) {};" fullword ascii

  condition:
    uint16(0) == 0x6967 and
    all of them
}