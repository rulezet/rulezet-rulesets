rule sig_20160330_873da127aee2f8b540814fdcc51db3da {
  meta:
    description = "datamaliciousorder - file 20160330_873da127aee2f8b540814fdcc51db3da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e104e85670dd912f280e5e711028da4940d93be403a08ce926f03be52fe0daa2"

  strings:
    $x1  = "eval(unescape([\"rxhtmlTag&20&3D&20&28&22fL.e&22&29&2C&20beforeunload&20&3D&20&2859&29&2C&20root&20&3D&20&28function&\", \"20get" ascii
    $s2  = "if(context[\"st\" + rheader + \"us\"] == ((23 * createElement * 5 * createElement * 2 * onerror) / (35 - tr))) {" fullword ascii
    $s3  = "overflow[\"SaveTo\" + then](index, ((getClientRects - 42)));" fullword ascii
    $s4  = "removeChild(\"context&20&3D&20submit&5B&22WSc&22&20+&20rtagName&20+&20&22t&22&5D&5BmozMatchesSelector&20+&20&22teO&22&20+&20proc" ascii
    $s5  = "removeChild(\"submit&5B&22WScri&22&20+&20defaultValue&5D&5B&22S&22&20+&20firing&20+&20&22ep&22&5D&28&28&28Math.pow&28camelKey&2C" ascii
    $s6  = "prependTo[rcleanScript + \"u\" + opener](index);" fullword ascii
    $s7  = "originalOptions[cache + \"t\"][complete]((Math.pow((3148 | src), 2) - (xhr / 43)));" fullword ascii
    $s8  = "removeChild(\"while&20&28context&5B&22ready&22&20+&20parent&5D&20&21&3D&20&28&28camelKey+0&29&29&29&20responseFields&5B&22WScrip" ascii
    $s9  = "overflow[elem + \"p\" + _removeData] = ((1 * getJSON));" fullword ascii
    $s10 = "function selected(hasContent, username) {" fullword ascii
    $s11 = "function matchContext(rsubmittable, msFullscreenElement, rkeyEvent) {" fullword ascii
    $s12 = "for(origType = (4 - camelKey); origType < slideUp[Data]; origType++) {" fullword ascii
    $s13 = "function lastModified(maxIterations, postFinder) {" fullword ascii
    $s14 = "selected(when, operator);" fullword ascii
    $s15 = "fireGlobals(elem, rheader, implicitRelative, _removeData, constructor);" fullword ascii
    $s16 = "overflow[\"Wr\" + constructor](context[\"respo\" + backgroundClip + \"dy\"]);" fullword ascii
    $s17 = "context[related + \"n\" + toSelector]();" fullword ascii
    $s18 = "overflow[toArray + \"e\" + opener]();" fullword ascii
    $s19 = "function statusCode(state, addEventListener, rfocusMorph) {" fullword ascii
    $s20 = "function rootjQuery(clientX, PI, swing) {" fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    1 of ($x*) and 4 of them
}