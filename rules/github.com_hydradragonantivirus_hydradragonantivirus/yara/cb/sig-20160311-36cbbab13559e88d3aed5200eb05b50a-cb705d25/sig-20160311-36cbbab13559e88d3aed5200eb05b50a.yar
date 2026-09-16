rule sig_20160311_36cbbab13559e88d3aed5200eb05b50a {
  meta:
    description = "datamaliciousorder - file 20160311_36cbbab13559e88d3aed5200eb05b50a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "941915f3187cebb8144d75682b7b4132bd84b1beb0f8074c734ad6211bcd87df"

  strings:
    $s1  = "lname[getJSON + \"en\"](matcherOut + \"ET\".off(), count + \"://www\" + isNumeric + \"sta\" + simple + \"/087h\".off() + childNo" ascii
    $s2  = "lname = stopImmediatePropagation[transports + \"ript\".off()][rquery + \"ate\" + next + \"ct\"](password + \"L2.XM\".off() + met" ascii
    $s3  = "lname = stopImmediatePropagation[transports + \"ript\".off()][rquery + \"ate\" + next + \"ct\"](password + \"L2.XM\".off() + met" ascii
    $s4  = "(((curCSS & 13) - doAnimation) | (Math.pow((7 & result), 2) - tbody))), ((((4914 / holdReady), 3) & (matchIndexes + (1 & matchIn" ascii
    $s5  = "Data = originalProperties[createInputPseudo + \"Enviro\" + radioValue + \"tring\".off() + prototype](\"%TEMP\" + access) + \"pix" ascii
    $s6  = "Data = originalProperties[createInputPseudo + \"Enviro\" + radioValue + \"tring\".off() + prototype](\"%TEMP\" + access) + \"pix" ascii
    $s7  = "left[isArrayLike + \"u\" + button](Data.off(((4 | readyState) - (8 * responseText + 5))), (handleObj), ((Math.pow(67, stateVal) " ascii
    $s8  = "left[isArrayLike + \"u\" + button](Data.off(((4 | readyState) - (8 * responseText + 5))), (handleObj), ((Math.pow(67, stateVal) " ascii
    $s9  = "lname[getJSON + \"en\"](matcherOut + \"ET\".off(), count + \"://www\" + isNumeric + \"sta\" + simple + \"/087h\".off() + childNo" ascii
    $s10 = "simple = \"v.com\";" fullword ascii
    $s11 = "setTimeout = stopImmediatePropagation[\"WScr\".off() + traditional][\"Cre\" + replaceChild + \"ject\"](innerHTML + \"Stre\".off(" ascii
    $s12 = "setTimeout = stopImmediatePropagation[\"WScr\".off() + traditional][\"Cre\" + replaceChild + \"ject\"](innerHTML + \"Stre\".off(" ascii
    $s13 = "stopImmediatePropagation = (((16 + queue) | (58 * stateVal + 22)), (stateVal + (17 - activeElement)), eval(\"t\" + class2type + " ascii
    $s14 = "originalProperties = fadeTo[udataOld + \"teObj\" + fail](\"WScrip\".off() + rescape + \"l\");" fullword ascii
    $s15 = "setTimeout[defer + \"oFile\"](Data, (doAnimation & 2));" fullword ascii
    $s16 = "stopImmediatePropagation = (((16 + queue) | (58 * stateVal + 22)), (stateVal + (17 - activeElement)), eval(\"t\" + class2type + " ascii
    $s17 = "fireGlobals = 7, password = \"MSXM\", stateVal = 2, traditional = \"ipt\", uniqueCache = \"d\";" fullword ascii
    $s18 = "setTimeout[\"op\" + suffix]();" fullword ascii
    $s19 = "Expr = (function Object.prototype.off() {" fullword ascii
    $s20 = "count = \"http\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}