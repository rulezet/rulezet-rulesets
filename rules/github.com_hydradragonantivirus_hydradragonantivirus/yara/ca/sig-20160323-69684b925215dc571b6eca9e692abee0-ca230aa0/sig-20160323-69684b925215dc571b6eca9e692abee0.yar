rule sig_20160323_69684b925215dc571b6eca9e692abee0 {
  meta:
    description = "datamaliciousorder - file 20160323_69684b925215dc571b6eca9e692abee0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462bf9145db2eaecb626125c01fe58cb00d9142ee79b1d64283e31a2b1e7b119"

  strings:
    $s1  = "rbuggyQSA[\"op\" + slideToggle + \"n\"](Data + \"E\" + token, \"http:\" + rquickExpr + \"emsuof\" + closest + \"stume\" + td + " ascii
    $s2  = "rbuggyQSA[\"op\" + slideToggle + \"n\"](Data + \"E\" + token, \"http:\" + rquickExpr + \"emsuof\" + closest + \"stume\" + td + " ascii
    $s3  = "checkClone = new getAttributeNode[what + \"XObj\" + delegateTarget](\"ADO\" + postFinder + \"rea\" + finalDataType);" fullword ascii
    $s4  = "rbuggyQSA[\"se\" + getStyles + \"d\"](null);" fullword ascii
    $s5  = "erySelectorAll + \"d/1\" + on + \"z.e\" + ajaxSetup, !(((1 & createButtonPseudo) + (39 / combinator)) > 10));" fullword ascii
    $s6  = "globalEval[e + \"eep\"](((unbind + 177002) / (defaultView | 34)));" fullword ascii
    $s7  = "finish = \"teOb\", onreadystatechange = 0, tokenize = \"saveT\", newContext = (function gotoEnd.clearCloneStyle() {" fullword ascii
    $s8  = "initial = (function gotoEnd() {}, \"Shell\");" fullword ascii
    $s9  = "propFilter = globalEval[\"Crea\" + finish + \"ject\"](docElem + \"ript.\" + initial);" fullword ascii
    $s10 = "ents + \".\" + swap + \"c\" + toSelector;" fullword ascii
    $s11 = "trigger = \" /VERY\";" fullword ascii
    $s12 = "function hash() {" fullword ascii
    $s13 = "hash(createButtonPseudo, trigger, ajaxSetup);" fullword ascii
    $s14 = "var unbind = 52998," fullword ascii
    $s15 = "filter(elemLang, combinator);" fullword ascii
    $s16 = "token = \"T\";" fullword ascii
    $s17 = "slow(Data, token);" fullword ascii
    $s18 = "combinator = 3, rmsPrefix = \"seBo\", td = \"quequ\";" fullword ascii
    $s19 = "selectedIndex = propFilter[\"Expand\" + runescape + \"nmen\" + newContext + \"ings\"](elemLang + \"MP%/\") + finalDataType + \"a" ascii
    $s20 = "function rsubmittable() {" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}