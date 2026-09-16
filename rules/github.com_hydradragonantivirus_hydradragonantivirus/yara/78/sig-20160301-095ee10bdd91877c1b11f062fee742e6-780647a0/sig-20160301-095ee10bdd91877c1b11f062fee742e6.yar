rule sig_20160301_095ee10bdd91877c1b11f062fee742e6 {
  meta:
    description = "datamaliciousorder - file 20160301_095ee10bdd91877c1b11f062fee742e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87a6bf3ed704d302732c3d38fd5d2702183db7df01ba861f47264eb299b23fd"

  strings:
    $s1 = "while(effectiveGrammar[(\"mat\\u0065\" + \"\\u0072ia\\u006c\", \"ve\" + \"\\u0074\\u0065r\" + \"\\u0061\\u006e\", \"\\u0069\\u00" ascii
    $s2 = "while(effectiveGrammar[(\"mat\\u0065\" + \"\\u0072ia\\u006c\", \"ve\" + \"\\u0074\\u0065r\" + \"\\u0061\\u006e\", \"\\u0069\\u00" ascii
    $s3 = "reflexCollective[(\"\\u0063o\\u006et\\u0072\" + \"ib\\u0075\" + \"\\u0074io\\u006e\", \"b\" + \"\\u0061l\" + \"\\u006ca\" + \"s" ascii
    $s4 = "boatEffective = ((([+!+[]])), this);" fullword ascii
    $s5 = "\"\\u006e\", \"\\u0074\\u0065x\\u0074\", function String.prototype.presumptionIdea() {" fullword ascii
    $s6 = "} catch(modifyYacht) {};" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    all of them
}