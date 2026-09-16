rule sig_20160301_71e6fdd874bbfff54f2e039755cc220b {
  meta:
    description = "datamaliciousorder - file 20160301_71e6fdd874bbfff54f2e039755cc220b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c20ff5bec0e1a9a55ae77586aa4e2348171a77588fee51a2597c1a376c9b31"

  strings:
    $s1 = "campaignAppeal = genealogyBar[(\"hobby\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"coordinationTariff\") + (\".scr\");" ascii
    $s2 = "while(neutralSkeleton[(\"republic\", \"import\", \"nose\", \"readystate\")] < ((145 - 91) - (50))) {" fullword ascii
    $s3 = "collectorMotivate = (((404 - 152) - (8 + 53)), this);" fullword ascii
    $s4 = "identicalDefect = (\"contribution\", \"banana\", function String.prototype.magazineAuthor() {" fullword ascii
    $s5 = "} catch(syntaxBureaucracy) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}