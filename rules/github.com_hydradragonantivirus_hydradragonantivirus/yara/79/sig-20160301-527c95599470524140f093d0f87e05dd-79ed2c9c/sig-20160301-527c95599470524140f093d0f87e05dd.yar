rule sig_20160301_527c95599470524140f093d0f87e05dd {
  meta:
    description = "datamaliciousorder - file 20160301_527c95599470524140f093d0f87e05dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937d0163acfe827fd4b7b6d94ba15f17cdfdbff2b404a46ee258003f7dc2ce4e"

  strings:
    $s1 = "while (finalCycle[(\"de\\u0070\" + \"\\u006f\\u0073\\u0069\\u0074\", \"vu\" + \"lga\" + \"r\", \"voca\\u006c\", \"\\u0069\\u006e" ascii
    $s2 = "combinationSession = (((166, 90, 14, 1) | (246, 0)), this);" fullword ascii
    $s3 = "} catch (periodPrologue) {};" fullword ascii
    $s4 = "dogOccasion = ballastCardinal[(\"pla\" + \"\\u0074f\" + \"\\u006frm\", function String.prototype.meditateQuarantine() {" fullword ascii
    $s5 = "while (finalCycle[(\"de\\u0070\" + \"\\u006f\\u0073\\u0069\\u0074\", \"vu\" + \"lga\" + \"r\", \"voca\\u006c\", \"\\u0069\\u006e" ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}