rule sig_20160301_fe94cfcd02188a046792291e1652180c {
  meta:
    description = "datamaliciousorder - file 20160301_fe94cfcd02188a046792291e1652180c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db34dae4990489e4d8dca9dfeb160d7533650ca641745d7d27ba27257cef56fe"

  strings:
    $s1 = "citationFragment = bandageOrganism[(\"autopilot\", \"civilization\", \"segment\", \"authority\", \"ExpandEnvironmentStrings\")](" ascii
    $s2 = ", \"%TEMP%/\")) + (\"pulse\", \"realization\", \"studentConfiguration\") + (\"individual\", \"legal\", \".scr\");" fullword ascii
    $s3 = "maximumGroup = (\"moment\", function String.prototype.postscriptAssistant() {" fullword ascii
    $s4 = "while(voyageTelevision[(\"readystate\")] < (3 ^ (5 ^ 2))) {" fullword ascii
    $s5 = "portalStatuette = ((82 / 2) * (2 ^ 1) * 2, this);" fullword ascii
    $s6 = "} catch(legionInspector) {};" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    all of them
}