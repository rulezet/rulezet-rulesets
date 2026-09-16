rule sig_20160301_2265a99c9a821f132c2fcd3695ec29bf {
  meta:
    description = "datamaliciousorder - file 20160301_2265a99c9a821f132c2fcd3695ec29bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5756cf0e64ae55ebf4302c091e5199aef17c34630ba0fd9ce68dc7017fd34b13"

  strings:
    $s1 = "netPaste = museumTelevision[(\"compositor\", \"transmission\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"profile\", \"m" ascii
    $s2 = "netPaste = museumTelevision[(\"compositor\", \"transmission\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"profile\", \"m" ascii
    $s3 = "while(conventionAlternative[(\"readystate\")] < ((24 * 5) / (Math.pow(57, 2) - 3219))) {" fullword ascii
    $s4 = "neutralSimulate = (((0 ^ 0) ^ (0 + 0)), this);" fullword ascii
    $s5 = "ort\", \"sprint\", \"formalCivilization\") + (\"centre\", function String.prototype.regimeApproximation() {" fullword ascii
    $s6 = "} catch(dictatePrivate) {};" fullword ascii

  condition:
    uint16(0) == 0x656e and
    all of them
}