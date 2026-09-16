rule sig_20160516_9a11a7407eb0c3c45ee7a6b7d1139757 {
  meta:
    description = "datamaliciousorder - file 20160516_9a11a7407eb0c3c45ee7a6b7d1139757.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e36c64117378f23cd33c3ef0938a4d996ce6cb984944cfad364b64a8f141bae1"

  strings:
    $s1  = "var talent=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vegetarian4())&&purport[\"c3RhdHVz\".vegetarian4()] +\"\"==\"MjAw\".v" ascii
    $s2  = "var talent=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vegetarian4())&&purport[\"c3RhdHVz\".vegetarian4()] +\"\"==\"MjAw\".v" ascii
    $s3  = "friendly = ((\"prosecutor\", \"voting\", \"durable\", \"governmental\", \"slNsnHlmwVMM\") + \"WunepqRHL\").vegetarian2();" fullword ascii
    $s4  = "contingency = ((\"geographic\", \"broader\", \"insincere\", \"twirl\", \"pxIlCYcKez\") + \"ymrnitwxe\").vegetarian2();" fullword ascii
    $s5  = "weasel = ((\"madrid\", \"range\", \"shopzilla\", \"presidential\", \"EhLOWoVa\") + \"dfFwiW\").vegetarian2();" fullword ascii
    $s6  = "String.prototype.vegetarian4 = function() {" fullword ascii
    $s7  = "String.prototype.vegetarian2 = function () {" fullword ascii
    $s8  = "String.prototype.vegetarian = function () {" fullword ascii
    $s9  = "var becoming = \"QWN0aXZlWE9iamVjdA==\".vegetarian4();" fullword ascii
    $s10 = "var chuckle =\"JVRFTVAl\".vegetarian4();" fullword ascii
    $s11 = "luminary = \"b3Blbg==\".vegetarian4();;" fullword ascii
    $s12 = "nsexuales\",\"fender\",\"accompanies\",\"fragmentary\",\"foray\",\"08\"), friendly)] = 0;" fullword ascii
    $s13 = "var kinswoman = czechs.pop().split(\"" fullword ascii
    $s14 = "var czechs = [becoming, soldiers,chuckle,  \"\"+\".\"+(\"militant\",\"births\",\"berkeley\",\"fallen\",\"continued\",\"measurabl" ascii
    $s15 = "var purport = new retrace(kinswoman[0]);" fullword ascii
    $s16 = "            purport[luminary]((\"barbados\",\"dunbar\",\"G\" + weasel) + (\"hymen\",\"determines\",\"genoese\",\"outlaw\",\"T\")" ascii
    $s17 = "var czechs = [becoming, soldiers,chuckle,  \"\"+\".\"+(\"militant\",\"births\",\"berkeley\",\"fallen\",\"continued\",\"measurabl" ascii
    $s18 = "            purport[luminary]((\"barbados\",\"dunbar\",\"G\" + weasel) + (\"hymen\",\"determines\",\"genoese\",\"outlaw\",\"T\")" ascii
    $s19 = "    purport[friendly + (\"heterodox\",\"foremast\",\"end\")]();" fullword ascii
    $s20 = "layout = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}