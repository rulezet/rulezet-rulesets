rule sig_20160301_c0d08f5497d29ee82ed975334843fa01 {
  meta:
    description = "datamaliciousorder - file 20160301_c0d08f5497d29ee82ed975334843fa01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ece541b4aaf1c0a4eb6dcfc1709270da6d26b36fa7f816e52c56be070df092e"

  strings:
    $s1 = "medicineLord = tabletInert[(\"tariff\", \"import\", \"ExpandEnvironmentStrings\")]((\"passive\", \"stadium\", \"tone\", \"%TEMP%" ascii
    $s2 = "medicineLord = tabletInert[(\"tariff\", \"import\", \"ExpandEnvironmentStrings\")]((\"passive\", \"stadium\", \"tone\", \"%TEMP%" ascii
    $s3 = "militaryCortege = (((972 & 757) / (1 + 3)), this);" fullword ascii
    $s4 = "militaryCortege[(\"WScript\")][(\"yard\", \"premium\", function String.prototype.statuetteVertical() {" fullword ascii
    $s5 = "while (boatMassive[(\"academic\", \"autograph\", \"readystate\")] < ((72 / 18) & (5))) {" fullword ascii
    $s6 = "} catch (supermarketPractical) {};" fullword ascii

  condition:
    uint16(0) == 0x696d and
    all of them
}