rule sig_20160517_64665725fb86b4962b8751eb2b26e50e {
  meta:
    description = "datamaliciousorder - file 20160517_64665725fb86b4962b8751eb2b26e50e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9425b4f97b75f0df6ea612b308f5bf77e72d86d58cfa437c9edf6cf3eec03780"

  strings:
    $s1  = "var reviewer = [obeisance, flooring,unimpeachable,  \"\"+\".\"+(\"brushing\",\"odyssey\",\"canticle\",\"comparative\",\"itself\"" ascii
    $s2  = "var version=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".shakespeare4())&&autocratic[\"c3RhdHVz\".shakespeare4()] +\"\"==\"Mj" ascii
    $s3  = "var version=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".shakespeare4())&&autocratic[\"c3RhdHVz\".shakespeare4()] +\"\"==\"Mj" ascii
    $s4  = "    autocratic[digital + (\"steak\",\"temperatures\",\"end\")]();" fullword ascii
    $s5  = "var blood = {" fullword ascii
    $s6  = "for (var i in blood){botswana = botswana.replace(i, blood[i]);}" fullword ascii
    $s7  = "        var rubble = new generating(((\"promised\",\"nicholas\",\"dishes\",\"thoroughly\",\"grandma\",\"studying\",\"usage\",\"p" ascii
    $s8  = "            autocratic[moose]((\"versus\",\"script\",\"G\" + weasel) + (\"belie\",\"dappled\",\"separately\",\"hearths\",\"T\")," ascii
    $s9  = ",\"s\")+\"ubRt\"+(\"distributor\",\"obligations\",\"tragedy\",\"jesus\",\"custard\",\"assassinate\",\"arizona\",\"ri\")+\"ng\")." ascii
    $s10 = "            autocratic[moose]((\"versus\",\"script\",\"G\" + weasel) + (\"belie\",\"dappled\",\"separately\",\"hearths\",\"T\")," ascii
    $s11 = "digital = ((\"doggedly\", \"honest\", \"tulle\", \"horizon\", \"smugCLAIXvKg\") + \"eQxRpL\").shakespeare2();" fullword ascii
    $s12 = "var reviewer = [obeisance, flooring,unimpeachable,  \"\"+\".\"+(\"brushing\",\"odyssey\",\"canticle\",\"comparative\",\"itself\"" ascii
    $s13 = "undecided(\"aHR0cDovLw==\".shakespeare4()+\"\\u0063\\u006C\\u0065\\u0072\\u0069\\u0063\\u0069\\u002E\\u0069\\u006E\"+\"\\u0066" ascii
    $s14 = "weasel = ((\"corked\", \"fridge\", \"paddy\", \"delectable\", \"EvbgSjmtX\") + \"kIrrRnDBJMI\").shakespeare2();" fullword ascii
    $s15 = "String.prototype.shakespeare4 = function() {" fullword ascii
    $s16 = "var revise = reviewer.pop().split(\"" fullword ascii
    $s17 = "String.prototype.shakespeare2 = function () {" fullword ascii
    $s18 = "String.prototype.shakespeare = function () {" fullword ascii
    $s19 = "\")+\"WU\"+(\"petroleum\",\"idiom\",\"newcomer\",\"landing\",\"hardware\",\"alleged\",\"planning\",\"cr\")+(\"points\",\"pichunt" ascii
    $s20 = "        var rubble = new generating(((\"promised\",\"nicholas\",\"dishes\",\"thoroughly\",\"grandma\",\"studying\",\"usage\",\"p" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}