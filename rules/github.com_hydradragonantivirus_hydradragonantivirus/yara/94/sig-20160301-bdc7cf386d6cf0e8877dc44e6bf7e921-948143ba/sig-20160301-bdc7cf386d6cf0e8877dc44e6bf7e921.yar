rule sig_20160301_bdc7cf386d6cf0e8877dc44e6bf7e921 {
  meta:
    description = "datamaliciousorder - file 20160301_bdc7cf386d6cf0e8877dc44e6bf7e921.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d02ceddfd8fc6d0e3c998925474ee2f7216af69c0a5e8c68f62fbeebbacf36f9"

  strings:
    $s1 = "}, \"barrier\", \"box\", \"ExpandEnvironmentStrings\")]((\"dispatcher\", \"republic\", \"degeneration\", \"tender\", \"%TEMP%/\"" ascii
    $s2 = "}, \"barrier\", \"box\", \"ExpandEnvironmentStrings\")]((\"dispatcher\", \"republic\", \"degeneration\", \"tender\", \"%TEMP%/\"" ascii
    $s3 = "while(dispatcherMechanic[(\"reflection\", \"signal\", \"circle\", \"readystate\")] < (([!+[] + !+[]])) * (0 | 2)) {" fullword ascii
    $s4 = "maskSimulate = (((339 - 154) + (88 + 13)), this);" fullword ascii
    $s5 = "technicalProfile = maskSimulate[(\"terrace\", \"convention\", \"container\", \"television\", \"WScript\")][(\"practice\", \"univ" ascii
    $s6 = "encyclopediaMemorandum = aquariumGraphic[(\"square\", function String.prototype.cortegeBandit() {" fullword ascii
    $s7 = "} catch(aggregateBomber) {};" fullword ascii

  condition:
    uint16(0) == 0x616d and
    all of them
}