rule sig_20160517_53c63e6b54c428694d202cc476360c64 {
  meta:
    description = "datamaliciousorder - file 20160517_53c63e6b54c428694d202cc476360c64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e61f2eb3b49e750eb489216bb0ad7179933e644fd63b6f09759964d21e33c3ad"

  strings:
    $s1  = "        affiliate[(predict + \"o\"+(\"woodwork\",\"andrews\",\"claims\",\"expenditure\",\"feint\",\"coxcomb\",\"absolve\",\"peda" ascii
    $s2  = "var puddles=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".abhorrent4())&&brutish[\"c3RhdHVz\".abhorrent4()] +\"\"==\"MjAw\".ab" ascii
    $s3  = "var puddles=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".abhorrent4())&&brutish[\"c3RhdHVz\".abhorrent4()] +\"\"==\"MjAw\".ab" ascii
    $s4  = ",\"bloodthirsty\",\"nebula\",\"watchword\",\"serious\",\"08\"), concern)] = 0;" fullword ascii
    $s5  = "gruesome = gruesome+ williams.shift();" fullword ascii
    $s6  = "weasel = ((\"unlock\", \"transfiguration\", \"covetous\", \"hearse\", \"ELMstpV\") + \"FXogiBAPKTl\").abhorrent2();" fullword ascii
    $s7  = "concern = ((\"wayside\", \"offense\", \"provost\", \"flour\", \"sdtWehxM\") + \"ubuXMgF\").abhorrent2();" fullword ascii
    $s8  = "predict = ((\"legendary\", \"searching\", \"bradley\", \"papua\", \"pueptmJi\") + \"znWreOMux\").abhorrent2();" fullword ascii
    $s9  = "String.prototype.abhorrent = function () {" fullword ascii
    $s10 = "String.prototype.abhorrent4 = function() {" fullword ascii
    $s11 = "var williams = [lexmark, resumes,oftentimes,  \"\"+\".\"+(\"laura\",\"lands\",\"concurrent\",\"economy\",\"arrest\",\"albion\"," ascii
    $s12 = "String.prototype.abhorrent2 = function () {" fullword ascii
    $s13 = "            brutish[models]((\"adequate\",\"widespread\",\"G\" + weasel) + (\"pertinacity\",\"cravat\",\"mince\",\"relate\",\"T" ascii
    $s14 = "        affiliate[(predict + \"o\"+(\"woodwork\",\"andrews\",\"claims\",\"expenditure\",\"feint\",\"coxcomb\",\"absolve\",\"peda" ascii
    $s15 = "            brutish[models]((\"adequate\",\"widespread\",\"G\" + weasel) + (\"pertinacity\",\"cravat\",\"mince\",\"relate\",\"T" ascii
    $s16 = "steel[williams.shift()](gruesome, fiddler, true);" fullword ascii
    $s17 = "var figure = {" fullword ascii
    $s18 = "var order = steel[williams.shift()](williams.shift());" fullword ascii
    $s19 = "steel = this;" fullword ascii
    $s20 = "var brutish = new confessor(trackback[0]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}