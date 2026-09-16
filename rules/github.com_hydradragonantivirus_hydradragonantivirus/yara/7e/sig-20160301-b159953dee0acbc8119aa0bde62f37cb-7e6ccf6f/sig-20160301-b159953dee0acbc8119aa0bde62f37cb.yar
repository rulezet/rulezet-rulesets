rule sig_20160301_b159953dee0acbc8119aa0bde62f37cb {
  meta:
    description = "datamaliciousorder - file 20160301_b159953dee0acbc8119aa0bde62f37cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea3a01274d534db39f4215ddf50d0c29b49cfc7afccd456f9c0b8b728ddb66d6"

  strings:
    $s1 = "imitationSuperman = ((26 - 25), this);" fullword ascii
    $s2 = "while (functionPrince[(\"\\u0072\" + \"eadys\\u0074\" + \"\\u0061te\")] < ((2 ^ 1) + (1 | 1))) {" fullword ascii
    $s3 = "chocolateMonster[(\"\\u0071ua\\u0072\" + \"\\u0061n\\u0074i\\u006e\" + \"\\u0065\", function String.prototype.clientLiterature()" ascii
    $s4 = "} catch (motivateMomentum) {};" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    all of them
}