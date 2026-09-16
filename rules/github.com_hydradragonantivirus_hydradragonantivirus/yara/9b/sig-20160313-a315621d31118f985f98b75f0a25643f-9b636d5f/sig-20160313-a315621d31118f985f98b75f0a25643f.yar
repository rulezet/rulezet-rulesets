rule sig_20160313_a315621d31118f985f98b75f0a25643f {
  meta:
    description = "datamaliciousorder - file 20160313_a315621d31118f985f98b75f0a25643f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03dd08951650308671ee0a66ce62df2398d4d127108109da790ce6333a7d6dde"

  strings:
    $x1  = "excess[\"o\" + doneName + \"en\"](defineProperty + \"E\" + holdReady, \"http\" + clientX + \"llo\" + scripts + \".com/7\" + boxS" ascii
    $s2  = "excess[\"o\" + doneName + \"en\"](defineProperty + \"E\" + holdReady, \"http\" + clientX + \"llo\" + scripts + \".com/7\" + boxS" ascii
    $s3  = "s = dirruns[\"Exp\" + fnOver + \"nvir\" + expando + \"ntSt\" + postDispatch + \"s\"](anim + \"/\") + setter + \"p\" + hasFocus +" ascii
    $s4  = "s = dirruns[\"Exp\" + fnOver + \"nvir\" + expando + \"ntSt\" + postDispatch + \"s\"](anim + \"/\") + setter + \"p\" + hasFocus +" ascii
    $s5  = "isTrigger = 680, anim = \"%TEMP%\", noGlobal = \"R\", percent = 12, nodeIndex = 184, nextSibling = 122;" fullword ascii
    $s6  = " 39), (Math.pow(lname, 2) - throws)) * (2 * (num / 19)) + ((nextSibling & 94) - (isTrigger / 10)))) / (((attrNames + 16) | (guar" ascii
    $s7  = "+ ((1 | src) + (48, defaultPrevented))) + (((4173 / buildParams), (Math.pow(19, guaranteedUnique) - 341), what * 13, (start - 30" ascii
    $s8  = "thead = \"e\", boxSizingReliable = \"0.e\", scripts = (function last() {}, \"guyff\"), style = \"write\";" fullword ascii
    $s9  = "document[stopped + \"pe\"] = ((35 | src) - (Math.pow(21, guaranteedUnique) - 407));" fullword ascii
    $s10 = "rtypenamespace = this[\"WScri\" + head];" fullword ascii
    $s11 = "cssHooks = this[\"WScri\" + head][\"Create\" + conditionFn + \"t\"](isPropagationStopped + \".Strea\" + indirect);" fullword ascii
    $s12 = "excess = this[\"WScri\" + head][\"Crea\" + structure + \"ject\"](disabled + \".XMLH\" + boxSizingReliableVal);" fullword ascii
    $s13 = ")) + -(src & 1)))) == (((((superMatcher / 8) + (percent | 12)) + ((realStringObj - 116) | src)) & (((3 * doScroll + 2), (split /" ascii
    $s14 = "indirect = \"m\", head = \"pt\";" fullword ascii
    $s15 = "excess[td + \"en\" + hasData]();" fullword ascii
    $s16 = "function xhrFields() {" fullword ascii
    $s17 = "function statusText() {" fullword ascii
    $s18 = "start = 31;" fullword ascii
    $s19 = "function appendTo() {" fullword ascii
    $s20 = "function insertAfter() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}