rule sig_20160301_0cca2e4a5f9f85ddf60e18896853f5b7 {
  meta:
    description = "datamaliciousorder - file 20160301_0cca2e4a5f9f85ddf60e18896853f5b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3f9aa0a0200d39bc16f26c4e3cb1ff93984980392ab5058692c67fe1ccadaf7"

  strings:
    $s1 = "articleSession = projectionMedicine[(\"ExpandEnvironmentStrings\")]((\"citation\", \"aspect\", \"%TEMP%/\")) + (\"clientColony\"" ascii
    $s2 = "articleSession = projectionMedicine[(\"ExpandEnvironmentStrings\")]((\"citation\", \"aspect\", \"%TEMP%/\")) + (\"clientColony\"" ascii
    $s3 = "] + !+[] + !+[]])) - (Math.pow(124, 2) - 15263)), this);" fullword ascii
    $s4 = "principleStimulus = (((([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[" ascii
    $s5 = "while(shuntTest[(\"group\", \"readystate\")] < ((31 ^ 127), (1 | 48), (4 | 4))) {" fullword ascii
    $s6 = "shuntTest[(\"tick\", function String.prototype.satelliteCalendar() {" fullword ascii
    $s7 = "} catch(indifferentSymptom) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}