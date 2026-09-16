rule sig_20160301_2cf195dcbdf882b262f7f72d6e91a3bf {
  meta:
    description = "datamaliciousorder - file 20160301_2cf195dcbdf882b262f7f72d6e91a3bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed69500fb5b0d688432411dbfdefb3f2407483eabde59404d6097e8b4fd1c5f7"

  strings:
    $x1 = "acousticBoat = conceptionOrder[(\"infection\", \"operator\", \"ExpandEnvironmentStrings\")]((\"phenomenon\", \"%TEMP%/\")) + (\"" ascii
    $s2 = "acousticBoat = conceptionOrder[(\"infection\", \"operator\", \"ExpandEnvironmentStrings\")]((\"phenomenon\", \"%TEMP%/\")) + (\"" ascii
    $s3 = "reservoirAbsorption = rocketDelta[(\"packing\", \"budget\", \"journal\", \"WScript\")][(\"globe\", \"CreateObject\")]((\"combina" ascii
    $s4 = "rocketDelta = (((63 * 3 + 18) - (378 / 7)), this);" fullword ascii
    $s5 = "while(reservoirAbsorption[(\"readystate\")] < ((1 * 0) + (2 * 2))) {" fullword ascii
    $s6 = "} catch(guideChance) {};" fullword ascii
    $s7 = " statusGenesis[(\"manager\", function String.prototype.licenceCategory() {" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    1 of ($x*) and all of them
}