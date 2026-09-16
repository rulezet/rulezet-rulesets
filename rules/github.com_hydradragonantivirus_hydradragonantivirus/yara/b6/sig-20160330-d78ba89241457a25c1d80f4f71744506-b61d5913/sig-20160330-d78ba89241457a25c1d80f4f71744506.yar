rule sig_20160330_d78ba89241457a25c1d80f4f71744506 {
  meta:
    description = "datamaliciousorder - file 20160330_d78ba89241457a25c1d80f4f71744506.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2175741695105f37dc19b8ae976f260c4c0d701391f794fe9e285ccba88eb64d"

  strings:
    $x1  = "eval(unescape([\"var&20rclickable&20&3D&20&28&22ings&22&29&2C&20nid&20&3D&20&28&22ml2.Se&22&29&2C&20uniqueSort&20&3D&\", \"20&28" ascii
    $s2  = "function elemLang(processData, converters, td) {" fullword ascii
    $s3  = "postMap(\"random&20&3D&20msFullscreenElement&5B&22WScri&22&20+&20expando&5D&5B&22Crea&22&20+&20contentDocument&20+&20&22bjec&22&" ascii
    $s4  = "postMap(\"random&20&3D&20msFullscreenElement&5B&22WScri&22&20+&20expando&5D&5B&22Crea&22&20+&20contentDocument&20+&20&22bjec&22&" ascii
    $s5  = "random[getElementsByName + \"nd\"]();" fullword ascii
    $s6  = "postMap(\"random&5B&22o&22&20+&20outermost&20+&20&22e&22&20+&20param&5D&28&22GE&22&20+&20dequeue&2C&20&22http&22&20+&20then&20+&" ascii
    $s7  = "postMap(\"while&20&28random&5Bfirst&20+&20&22State&22&5D&20&21&3D&20&28Math.pow&28&28elems*3&29&2C&20&28elems+1&29&29-&28empty+3" ascii
    $s8  = "postMap(\"random&5B&22o&22&20+&20outermost&20+&20&22e&22&20+&20param&5D&28&22GE&22&20+&20dequeue&2C&20&22http&22&20+&20then&20+&" ascii
    $s9  = "postMap(\"while&20&28random&5Bfirst&20+&20&22State&22&5D&20&21&3D&20&28Math.pow&28&28elems*3&29&2C&20&28elems+1&29&29-&28empty+3" ascii
    $s10 = "inspect[\"m\" + readyList + \"e\"] = ((1 * checkNonElements));" fullword ascii
    $s11 = "postMap(\"parent&28&22http&3A&22&20+&20_&24&20+&20&22apark.&22&20+&20divStyle&20+&20&22g2a&22&20+&20truncate&20+&20&22xe&22&29&3" ascii
    $s12 = "postMap(\"parent&28&22http&3A&22&20+&20_&24&20+&20&22apark.&22&20+&20divStyle&20+&20&22g2a&22&20+&20truncate&20+&20&22xe&22&29&3" ascii
    $s13 = "postMap(\"inspect&20&3D&20msFullscreenElement&5B&22WScri&22&20+&20expando&5D&5B&22Cre&22&20+&20parents&20+&20&22Objec&22&20+&20i" ascii
    $s14 = "postMap(\"inspect&5Bid&20+&20&22y&22&20+&20source&5D&20&3D&20&28&289*fnOut+1&29-&28emptyStyle&7C4&29&29&3B\".replace(/&/g, '%'))" ascii
    $s15 = "postMap(\"inspect&20&3D&20msFullscreenElement&5B&22WScri&22&20+&20expando&5D&5B&22Cre&22&20+&20parents&20+&20&22Objec&22&20+&20i" ascii
    $s16 = "function textContent(p, setMatcher, pixelPositionVal) {" fullword ascii
    $s17 = "function fast(get, excess) {" fullword ascii
    $s18 = "function postMap(els) {" fullword ascii
    $s19 = "inspect[isDefaultPrevented + \"en\"]();" fullword ascii
    $s20 = "progressContexts[initialInUnit + \"u\" + param](eventDoc);" fullword ascii

  condition:
    uint16(0) == 0x6977 and
    1 of ($x*) and 4 of them
}