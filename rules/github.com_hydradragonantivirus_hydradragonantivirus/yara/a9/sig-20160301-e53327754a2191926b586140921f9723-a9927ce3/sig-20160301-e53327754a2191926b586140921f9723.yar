rule sig_20160301_e53327754a2191926b586140921f9723 {
  meta:
    description = "datamaliciousorder - file 20160301_e53327754a2191926b586140921f9723.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46377de800a22ad18d7ec21d86202ce92dca206e48a292fc0f992d5c1ae012b3"

  strings:
    $s1 = "pulseBudget = ((([+!+[]])), this);" fullword ascii
    $s2 = "while(arsenalAdministration[(\"\\u0074u\\u006e\" + \"\\u006eel\", \"l\\u0069c\\u0065n\" + \"c\\u0065\", \"i\\u006da\\u0067\\u006" ascii
    $s3 = "while(arsenalAdministration[(\"\\u0074u\\u006e\" + \"\\u006eel\", \"l\\u0069c\\u0065n\" + \"c\\u0065\", \"i\\u006da\\u0067\\u006" ascii
    $s4 = "arcticCybernetics[(\"or\\u0067a\\u006e\", function String.prototype.clientMate() {" fullword ascii
    $s5 = "} catch(acousticRegenerate) {};" fullword ascii

  condition:
    uint16(0) == 0x7570 and
    all of them
}