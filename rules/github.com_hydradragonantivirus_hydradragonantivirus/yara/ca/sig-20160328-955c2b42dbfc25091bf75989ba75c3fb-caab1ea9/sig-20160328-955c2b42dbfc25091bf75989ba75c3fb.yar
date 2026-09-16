rule sig_20160328_955c2b42dbfc25091bf75989ba75c3fb {
  meta:
    description = "datamaliciousorder - file 20160328_955c2b42dbfc25091bf75989ba75c3fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a487266badcc64023276e5f373668fda30286746323924cc99bbf7fbf7590e6f"

  strings:
    $s1  = "        rjsonp[\"WScri\" + dirruns][\"Sleep\"]((Math.pow((3140 | amd), 2) - (Math.pow(gotoEnd, 2) - protocol)));" fullword ascii
    $s2  = "    fns(keepData(\"what%5Brclickable%20+%20%22e%22%20+%20runescape%5D%28%22G%22%20+%20newUnmatched%2C%20%22http%22%20+%20setAttr" ascii
    $s3  = "function disableScript(guid) {" fullword ascii
    $s4  = "            what = hasDuplicate[\"WScrip\" + factory][\"Cre\" + cssFn + \"ect\"](scripts[getElementsByClassName]);" fullword ascii
    $s5  = "    if (what[\"sta\" + parentNode] == ((Math.pow(genFx, 2) - defaultValue) / (22 | handlerQueue))) {" fullword ascii
    $s6  = "    while (what[\"readyS\" + checkNonElements] != ((resolve - 37))) hasDuplicate[\"WSc\" + results][\"Sle\" + children](((ajaxTr" ascii
    $s7  = "t, 169, original) & (42 * reset + 24)));" fullword ascii
    $s8  = "            what[\"se\" + getAll]();" fullword ascii
    $s9  = "attrHandle[isXML + \"p\" + checkContext] = each;" fullword ascii
    $s10 = "    while (what[\"readyS\" + checkNonElements] != ((resolve - 37))) hasDuplicate[\"WSc\" + results][\"Sle\" + children](((ajaxTr" ascii
    $s11 = "        owner(genFx, rscriptTypeMasked, border);" fullword ascii
    $s12 = "modified(rinputs, factory, location, contents, outermostContext);" fullword ascii
    $s13 = "function modified() {" fullword ascii
    $s14 = "function newContext() {" fullword ascii
    $s15 = "relative();" fullword ascii
    $s16 = "function stateVal() {" fullword ascii
    $s17 = "function opener() {" fullword ascii
    $s18 = "function keepData(th) {" fullword ascii
    $s19 = "function relative(view, htmlPrefilter, indirect) {" fullword ascii
    $s20 = "opener(genFx);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}