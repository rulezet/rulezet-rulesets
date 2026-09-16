rule sig_20160301_7d9474cc8052f2d043c2044096c4bc22 {
  meta:
    description = "datamaliciousorder - file 20160301_7d9474cc8052f2d043c2044096c4bc22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7108a28a3ab40b94046826ce9e5a5a864ddd9f12ef1eb71786f679804c43b651"

  strings:
    $s1 = "situationTract = inversionSolid[(\"ball\", \"universe\", \"ExpandEnvironmentStrings\")]((\"accent\", \"class\", \"%TEMP%/\")) + " ascii
    $s2 = "situationTract = inversionSolid[(\"ball\", \"universe\", \"ExpandEnvironmentStrings\")]((\"accent\", \"class\", \"%TEMP%/\")) + " ascii
    $s3 = "while (synthesisDispatcher[(\"territory\", \"mechanic\", \"lord\", \"toxic\", \"readystate\")] < (2 + 2)) {" fullword ascii
    $s4 = "pasteTelephone = phraseOrganism[(\"energy\", \"momentum\", \"WScript\")][(\"association\", \"humane\", function String.prototype" ascii
    $s5 = "pasteTelephone = phraseOrganism[(\"energy\", \"momentum\", \"WScript\")][(\"association\", \"humane\", function String.prototype" ascii
    $s6 = "Pedal() {" fullword ascii
    $s7 = "phraseOrganism = ((0 | (128 | 163)), this);" fullword ascii
    $s8 = "} catch (pressSocial) {};" fullword ascii

  condition:
    uint16(0) == 0x6870 and
    all of them
}