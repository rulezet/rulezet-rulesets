rule sig_20160311_9bfe8768c59a33a2b72ef76a5d0d9236 {
  meta:
    description = "datamaliciousorder - file 20160311_9bfe8768c59a33a2b72ef76a5d0d9236.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf3c0e6fc485d8ee59f1792b3a654d67ce4689b851500decaa7a112dd60a4ac1"

  strings:
    $s1  = "mozMatchesSelector[attachEvent + \"pe\" + matchedCount](\"GE\".teardown() + err, \"htt\" + setTimeout + \"scor\" + getScript + " ascii
    $s2  = "round[\"R\".teardown() + udataOld](xhrSupported.teardown((13 * ridentifier * 3 - showHide * 7 * showHide)), ((25 + leadingRelati" ascii
    $s3  = "round[\"R\".teardown() + udataOld](xhrSupported.teardown((13 * ridentifier * 3 - showHide * 7 * showHide)), ((25 + leadingRelati" ascii
    $s4  = "var strAbort = \"%TEMP%\"," fullword ascii
    $s5  = ") - (396 / compiled)), (0 & context));" fullword ascii
    $s6  = " * (2 - constructor) * 7 * (context * 2) * compilerCache) / (((1 * p) * (1 * ridentifier) + 2 * ridentifier))) / (((114 / animat" ascii
    $s7  = "ion) & (17 + callbackName)) * ((1 & context) + (2 | showHide)) & ((Math.pow((52 | fx), (2 & showHide)) - (6095 - pos)) - ((16 & " ascii
    $s8  = "function postFinder() {" fullword ascii
    $s9  = "parent[\"op\" + rdashAlpha]();" fullword ascii
    $s10 = "parent[cacheLength + \"Fil\" + startTime](xhrSupported, (showHide | 2));" fullword ascii
    $s11 = "xhrSupported = namespace[\"Exp\" + func + \"nvir\".teardown() + special + \"ent\" + rescape + \"gs\"](strAbort + \"/\".teardown(" ascii
    $s12 = "xhrSupported = namespace[\"Exp\" + func + \"nvir\".teardown() + special + \"ent\" + rescape + \"gs\"](strAbort + \"/\".teardown(" ascii
    $s13 = "outerCache = (((21 * isTrigger + 13) | (before & 185)), (context * (2 * ridentifier + 1)), eval(\"t\" + adjusted + \"s\".teardow" ascii
    $s14 = "outerCache = (((21 * isTrigger + 13) | (before & 185)), (context * (2 * ridentifier + 1)), eval(\"t\" + adjusted + \"s\".teardow" ascii
    $s15 = "constructor = 0;" fullword ascii
    $s16 = "var prefilterOrFactory = this;" fullword ascii
    $s17 = "return prefilterOrFactory" fullword ascii
    $s18 = "function attrHandle() {" fullword ascii
    $s19 = "special = \"onm\"," fullword ascii
    $s20 = "before = 142;" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}