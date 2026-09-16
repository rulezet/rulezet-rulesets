rule sig_20160518_43999e6711e91c32cf8e61d60a38399b {
  meta:
    description = "datamaliciousorder - file 20160518_43999e6711e91c32cf8e61d60a38399b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab9f474ce82c55ce3895dfbd0cb035c6280e97fcabacd9f535c6bd7cb4908f13"

  strings:
    $s1  = "var tussle = [temporary, heavily,impartiality,  \"\"+\".\"+(\"maneuver\",\"calibration\",\"abating\",\"hungarian\",\"legion\",\"" ascii
    $s2  = "var temporary = \"QWenumerationN0aXZenumerationlWE9iaenumerationmVjdA=enumeration=\".rehearsal4();" fullword ascii
    $s3  = "        birthright[(baize + \"o\"+(\"gazette\",\"redound\",\"petroleum\",\"effigy\",\"flirtation\",\"common\",\"established\",\"" ascii
    $s4  = "var baritone=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rehearsal4())&&colonial[\"c3RhdHVz\".rehearsal4()] +\"\"==\"MjAw\"." ascii
    $s5  = "var baritone=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rehearsal4())&&colonial[\"c3RhdHVz\".rehearsal4()] +\"\"==\"MjAw\"." ascii
    $s6  = "weasel = ((\"azerbaijan\", \"incoherent\", \"drain\", \"travelling\", \"ErjaELyRH\") + \"qYFSaYal\").rehearsal2();" fullword ascii
    $s7  = "ginger = ginger+ tussle.shift();" fullword ascii
    $s8  = "baize = ((\"participant\", \"connecting\", \"hired\", \"cricket\", \"pgiopCQ\") + \"VpFhIxfbC\").rehearsal2();" fullword ascii
    $s9  = "var tussle = [temporary, heavily,impartiality,  \"\"+\".\"+(\"maneuver\",\"calibration\",\"abating\",\"hungarian\",\"legion\",\"" ascii
    $s10 = "String.prototype.rehearsal2 = function () {" fullword ascii
    $s11 = "var glorify = tussle.pop().split(\">\");" fullword ascii
    $s12 = "function profiles(endangered, concomitant) {" fullword ascii
    $s13 = "String.prototype.rehearsal = function () {" fullword ascii
    $s14 = "String.prototype.rehearsal4 = function() {" fullword ascii
    $s15 = "        birthright[(baize + \"o\"+(\"gazette\",\"redound\",\"petroleum\",\"effigy\",\"flirtation\",\"common\",\"established\",\"" ascii
    $s16 = "        var ginger = tureen + \"/\" + concomitant ;" fullword ascii
    $s17 = "totter = \"_F2_\";" fullword ascii
    $s18 = "prize = \"b3Blbg==\".rehearsal4();;" fullword ascii
    $s19 = "  chink = [];" fullword ascii
    $s20 = "var impartiality =\"JVenumerationRFTVenumerationAl\".rehearsal4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}