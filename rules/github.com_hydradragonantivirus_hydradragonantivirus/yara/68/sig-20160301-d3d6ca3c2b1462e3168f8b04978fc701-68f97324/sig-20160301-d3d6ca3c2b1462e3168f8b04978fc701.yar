rule sig_20160301_d3d6ca3c2b1462e3168f8b04978fc701 {
  meta:
    description = "datamaliciousorder - file 20160301_d3d6ca3c2b1462e3168f8b04978fc701.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79a6f2ceb0f095b57fb59fd38a8c040cbc48542498641aceeae599c78da587f1"

  strings:
    $s1 = "indexInterpretation = doubleDefect[(\"position\", \"method\", \"violet\", \"ExpandEnvironmentStrings\")]((\"beast\", \"%TEMP%/\"" ascii
    $s2 = "indexInterpretation = doubleDefect[(\"position\", \"method\", \"violet\", \"ExpandEnvironmentStrings\")]((\"beast\", \"%TEMP%/\"" ascii
    $s3 = "projectContact = (((1 * 2) * (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]]) * ([!+[] + !+[] + !+[]]))), this);" fullword ascii
    $s4 = "while(astronautAcademic[(\"collision\", \"readystate\")] < ((32 + 156) / ((((([!+[] + !+[]]) * ([!+[] + !+[]])) + \"\" + (([!+[]" ascii
    $s5 = "while(astronautAcademic[(\"collision\", \"readystate\")] < ((32 + 156) / ((((([!+[] + !+[]]) * ([!+[] + !+[]])) + \"\" + (([!+[]" ascii
    $s6 = "charmOrganize = (\"infection\", \"canal\", \"phrase\", function String.prototype.princeBarrel() {" fullword ascii
    $s7 = "} catch(cabinBomber) {};" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}