rule sig_20160301_03834ea85434323b87ca4ba03588ba84 {
  meta:
    description = "datamaliciousorder - file 20160301_03834ea85434323b87ca4ba03588ba84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "315392804d31f2f831ea73b25aaa9af325ccfb4f9eb610f1a5594407bd9dfe16"

  strings:
    $s1 = "classificationBillion = autographDiagram[(\"alphabet\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"identical\", \"portra" ascii
    $s2 = "classificationBillion = autographDiagram[(\"alphabet\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"identical\", \"portra" ascii
    $s3 = "while(meridianMinor[(\"element\", \"stimulus\", \"meridian\", \"morgue\", \"readystate\")] < ((195 / 39) & (([!+[] + !+[]]) * ([" ascii
    $s4 = "while(meridianMinor[(\"element\", \"stimulus\", \"meridian\", \"morgue\", \"readystate\")] < ((195 / 39) & (([!+[] + !+[]]) * ([" ascii
    $s5 = "} catch(extremeGenealogy) {};" fullword ascii
    $s6 = "articleHandicap = (((0 ^ 3) + (([!+[] + !+[] + !+[]]) * ([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]]))), this);" fullword ascii
    $s7 = "aviationRotation[(\"formula\", \"regression\", \"protector\", function String.prototype.antennaScalpel() {" fullword ascii

  condition:
    uint16(0) == 0x7261 and
    all of them
}