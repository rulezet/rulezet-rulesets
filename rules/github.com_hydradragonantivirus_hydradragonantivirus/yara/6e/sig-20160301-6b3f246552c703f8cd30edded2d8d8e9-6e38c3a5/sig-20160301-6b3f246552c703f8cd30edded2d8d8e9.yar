rule sig_20160301_6b3f246552c703f8cd30edded2d8d8e9 {
  meta:
    description = "datamaliciousorder - file 20160301_6b3f246552c703f8cd30edded2d8d8e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c40a3c00b0a7abe90d7cd1570af32f1d96fec83ded67e6e67c329fd4dc5d0a"

  strings:
    $s1 = "sportComment = (((1 & 1) + (0 + 0)), this);" fullword ascii
    $s2 = "presentImitate = sportComment[(\"h\\u0065\\u0072\" + \"b\", \"d\\u0065fe\\u0063t\", function String.prototype.typicalDiction() {" ascii
    $s3 = "while (stateAddress[(\"ca\\u0070\" + \"i\" + \"\\u0074\\u0075\\u006cati\" + \"\\u006f\" + \"\\u006e\", \"\\u0073\" + \"ol\\u006f" ascii
    $s4 = "while (stateAddress[(\"ca\\u0070\" + \"i\" + \"\\u0074\\u0075\\u006cati\" + \"\\u006f\" + \"\\u006e\", \"\\u0073\" + \"ol\\u006f" ascii
    $s5 = "} catch (commerceStadium) {};" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    all of them
}