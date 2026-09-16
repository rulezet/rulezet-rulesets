rule sig_20160301_03119e7c1821bb51de2c2a737d75e0f4 {
  meta:
    description = "datamaliciousorder - file 20160301_03119e7c1821bb51de2c2a737d75e0f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "412ec308935abffa8f311025d1366400cf974de8b1e6430b4a397ef319fdd35d"

  strings:
    $s1 = "}, \"strategic\", \"%TEMP%/\")) + (\"ceremony\", \"sponsor\", \"legionLegion\") + (\".scr\");" fullword ascii
    $s2 = "while(humanePositive[(\"volt\", \"readystate\")] < ((58 - 39) - (2 ^ 13))) {" fullword ascii
    $s3 = "bandInvest = (((([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[]])) + (254 & 238)), this" ascii
    $s4 = "bandInvest = (((([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[]])) + (254 & 238)), this" ascii
    $s5 = "blockadePremium = acrobatCitation[(\"profile\", \"universe\", \"ExpandEnvironmentStrings\")]((\"anecdote\", function String.prot" ascii
    $s6 = "} catch(bananaPremium) {};" fullword ascii
    $s7 = "blockadePremium = acrobatCitation[(\"profile\", \"universe\", \"ExpandEnvironmentStrings\")]((\"anecdote\", function String.prot" ascii

  condition:
    uint16(0) == 0x6162 and
    all of them
}