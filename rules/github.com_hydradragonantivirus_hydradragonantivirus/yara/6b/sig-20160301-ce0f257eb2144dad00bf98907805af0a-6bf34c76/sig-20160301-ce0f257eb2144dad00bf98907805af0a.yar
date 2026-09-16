rule sig_20160301_ce0f257eb2144dad00bf98907805af0a {
  meta:
    description = "datamaliciousorder - file 20160301_ce0f257eb2144dad00bf98907805af0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224f77649d2ffb62220d4fa0b07f714e04731bc687133bfa9d47c63518855a03"

  strings:
    $s1 = "while(journalActor[(\"p\\u0072\" + \"\\u0069\" + \"\\u006d\\u0069t\\u0069v\" + \"\\u0065\", function String.prototype.startMotor" ascii
    $s2 = "memoirsService = (((73 | 31), (86 / 43), 1), this);" fullword ascii
    $s3 = "} catch(obligationMuseum) {};" fullword ascii

  condition:
    uint16(0) == 0x656d and
    all of them
}