rule sig_20160301_ef384611c8b01e13adb8d50a65de34c0 {
  meta:
    description = "datamaliciousorder - file 20160301_ef384611c8b01e13adb8d50a65de34c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "376c6fa963088d70a14dd6e0f1367f61e37beba9230d8288951ce20c314397fa"

  strings:
    $x1 = "licenceArsenal = managerCivilization[(\"peak\", \"discrete\", \"reflex\", \"operator\", \"ExpandEnvironmentStrings\")]((\"%TEMP%" ascii
    $s2 = "licenceArsenal = managerCivilization[(\"peak\", \"discrete\", \"reflex\", \"operator\", \"ExpandEnvironmentStrings\")]((\"%TEMP%" ascii
    $s3 = "symptomRegulate = (((32 + 79) + (Math.pow(126, 2) - 15702)), this);" fullword ascii
    $s4 = "while (instructionPreservative[(\"anatomy\", \"readystate\")] < ((8 + 11) - (15 & 15))) {" fullword ascii
    $s5 = "batteryOrder[(\"practical\", \"medical\", \"write\")](instructionPreservative[(\"triumph\", \"model\", function String.prototype" ascii
    $s6 = "} catch (cathedralReservoir) {};" fullword ascii
    $s7 = "batteryOrder[(\"practical\", \"medical\", \"write\")](instructionPreservative[(\"triumph\", \"model\", function String.prototype" ascii

  condition:
    uint16(0) == 0x7973 and
    1 of ($x*) and all of them
}