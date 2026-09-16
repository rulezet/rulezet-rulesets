rule sig_20160328_6e7d25fe69374ce5cbdbabefb079bb4e {
  meta:
    description = "datamaliciousorder - file 20160328_6e7d25fe69374ce5cbdbabefb079bb4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4307395e18dc360ddc875658a1c9c19c75b91b2395db7f9904ede3fcd77aec47"

  strings:
    $s1  = " if(onabort[exports + \"tus\"] == ((overrideMimeType & 511) - (unbind / 24))) {" fullword ascii
    $s2  = "  rrun[\"WScrip\" + method][\"Sleep\"]((5000 & (Math.pow(completeDeferred, 2) - nidselect)));" fullword ascii
    $s3  = "  fixHook[wrapInner + \"pt\"][cos](((Math.pow(source, 2) - getElementsByTagName) / (103, charCode, 132, merge)));" fullword ascii
    $s4  = " while(onabort[\"ready\" + before] != ((getResponseHeader + 6) - (rbracket - 37))) attrId[\"WScr\" + defaultValue][\"S\" + rattr" ascii
    $s5  = " while(onabort[\"ready\" + before] != ((getResponseHeader + 6) - (rbracket - 37))) attrId[\"WScr\" + defaultValue][\"S\" + rattr" ascii
    $s6  = "rrun = attrId = fixHook = disabled = risSimple.delegateTarget();" fullword ascii
    $s7  = "origType[\"t\" + dequeue + \"e\"] = ((227, reject, 79, focus) - (33 & doScroll));" fullword ascii
    $s8  = "uotes + \"p\"](((traditional | 129) - (isSimulated * 5 * isSimulated * 3)));" fullword ascii
    $s9  = "  origType[proxy + \"pe\" + returnTrue]();" fullword ascii
    $s10 = "function addGetHookIf(_data) {" fullword ascii
    $s11 = " fnOut(elementMatcher(\"soFar%20%3D%20rrun%5B%22WScri%22%20+%20slideUp%5D%5B%22Cre%22%20+%20set%20+%20%22Obje%22%20+%20rdisplays" ascii
    $s12 = "  soFar[originalEvent + \"u\" + returnTrue](interval);" fullword ascii
    $s13 = "  origType[\"SaveTo\" + checked](interval, ((143, pointerleave, 171, qsa) | (2 & isSimulated)));" fullword ascii
    $s14 = " fnOut(elementMatcher(\"soFar%20%3D%20rrun%5B%22WScri%22%20+%20slideUp%5D%5B%22Cre%22%20+%20set%20+%20%22Obje%22%20+%20rdisplays" ascii
    $s15 = " fnOut(elementMatcher(\"interval%20%3D%20soFar%5BboxSizingReliable%20+%20%22and%22%20+%20propFix%20+%20%22iro%22%20+%20dataAttr%" ascii
    $s16 = "function matchAnyContext() {" fullword ascii
    $s17 = "realStringObj(send, defaultValue);" fullword ascii
    $s18 = "function realStringObj(cur, modified, queue) {" fullword ascii
    $s19 = "function sort(name, each, bySet) {" fullword ascii
    $s20 = "function rbuggyMatches(tag) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}