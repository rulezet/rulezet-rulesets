rule sig_20160313_18b47e3fabd3ba9886ea84e62903101c {
  meta:
    description = "datamaliciousorder - file 20160313_18b47e3fabd3ba9886ea84e62903101c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28c21ee307c1e44946418839b278a436865bfbb64941a0d9ba0269b450a3557"

  strings:
    $s1  = "ct[\"op\" + define](\"G\" + inArray, \"http:/\" + constructor + \"llog\" + beforeunload + \"com/7\" + noGlobal + \"xe\", !(((((1" ascii
    $s2  = "ct[\"op\" + define](\"G\" + inArray, \"http:/\" + constructor + \"llog\" + beforeunload + \"com/7\" + noGlobal + \"xe\", !(((((1" ascii
    $s3  = " | ((1 + -createTween) & (0 & createTween))))) == (((((855 / fixHooks) - (7, disable)) - ((45 - postFilter))) | 1) | ((((Math.po" ascii
    $s4  = "pdataOld[clone + \"oFi\" + after](method, ((252 / postFinder) - (16 + inspected)));" fullword ascii
    $s5  = "getClientRects[dataTypeExpression + \"un\"](method, (1 - createTween), ((38 | triggered) - (65 - setMatcher)));" fullword ascii
    $s6  = "w(attrNames, 2) - rbuggyQSA), (92 | implicitRelative), (Math.pow(19, tbody) - 333))) - (tbody * (26 + len), (7 * delay - (81 - c" ascii
    $s7  = " setter, 3) * (accepts, 173, tbody))) + (((6 - isSimulated) | (11, preFilter, 235, compile)) | (((20 - filters) | (1 * compile))" ascii
    $s8  = "method = cleanData[\"Exp\" + boxSizingReliableVal + \"Envi\" + attrs + \"mentS\" + matcherIn + \"s\"](rhash + \"MP%/\") + swap +" ascii
    $s9  = "tbody = 2, rhash = \"%TE\", fix = \"ty\", getById = \"pt\", define = \"en\";" fullword ascii
    $s10 = "en) * (1 * tbody)) * 3 * ((writable / 9) | (compile | 0)) / ((len | 2) * (removeClass - 46) * (delegateCount + 6), (status, 192," ascii
    $s11 = "method = cleanData[\"Exp\" + boxSizingReliableVal + \"Envi\" + attrs + \"mentS\" + matcherIn + \"s\"](rhash + \"MP%/\") + swap +" ascii
    $s12 = "pdataOld = this[timers + \"t\"][mouseenter + \"eObj\" + removeEvent](\"ADOD\" + w + \"eam\");" fullword ascii
    $s13 = "ct = this[\"WSc\" + isHidden][\"Create\" + cssExpand + \"ct\"](prop + \"2.XMLH\" + pos);" fullword ascii
    $s14 = "ct[collection + \"nd\"]();" fullword ascii
    $s15 = "amd = this[\"WScr\" + matcherOut];" fullword ascii
    $s16 = "compile = 0;" fullword ascii
    $s17 = "identifier = unshift.leadingRelative();" fullword ascii
    $s18 = "teardown = \"posit\";" fullword ascii
    $s19 = "function apply() {" fullword ascii
    $s20 = "apply();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}