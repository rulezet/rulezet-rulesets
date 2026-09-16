rule sig_20160330_66f0999a3dbf5c750dc6abf7574e1a15 {
  meta:
    description = "datamaliciousorder - file 20160330_66f0999a3dbf5c750dc6abf7574e1a15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb69199433f0e11a8d002fc6a8665e4d672c32bc11590b042735ad6117d0b75"

  strings:
    $x1  = "eval(unescape([\"extra&20&3D&20&28&22m/vU4V&22&29&3B&20v&20&3D&20&2834&29&3B&20tweener&20&3D&20&28&22mo&22&29&3B&20ma\", \"tchEx" ascii
    $s2  = "function rheaders(attributes, keepScripts, tokenize) {" fullword ascii
    $s3  = "ownerDocument(\"index&20&3D&20conv&5B&22WSc&22&20+&20currentTarget&5D&5B&22Creat&22&20+&20argument&20+&20&22t&22&5D&28n&20+&20&2" ascii
    $s4  = "ownerDocument(\"index&20&3D&20conv&5B&22WSc&22&20+&20currentTarget&5D&5B&22Creat&22&20+&20argument&20+&20&22t&22&5D&28n&20+&20&2" ascii
    $s5  = "selection[isArrayLike + \"p\" + fnOver] = ((38 | fixHook) - (96 - old));" fullword ascii
    $s6  = "for(filter = ((1 + -start) | (0 / setter)); filter < init[showHide + \"th\"]; filter++) {" fullword ascii
    $s7  = "ownerDocument(\"selection&20&3D&20rmsPrefix&5BfcamelCase&20+&20&22t&22&5D&5BleadingRelative&20+&20&22eOb&22&20+&20manipulationTa" ascii
    $s8  = "rheaders(collection, match, realStringObj);" fullword ascii
    $s9  = "function insertAfter(maxWidth, hasContent) {" fullword ascii
    $s10 = "diff[\"se\" + match + \"d\"]();" fullword ascii
    $s11 = "selection[setDocument + \"pe\" + match]();" fullword ascii
    $s12 = "selection[offsetHeight + \"ToF\" + m](cloneCopyEvent, ((84 / constructor)));" fullword ascii
    $s13 = "index[\"Ru\" + match](cloneCopyEvent);" fullword ascii
    $s14 = "if(diff[\"st\" + checkOn + \"us\"] == ((responses | 1) * (extend / 35) * cur * 5 * (cur))) {" fullword ascii
    $s15 = "ownerDocument(\"while&20&28diff&5Bhash&20+&20&22ySta&22&20+&20replaceWith&5D&20&21&3D&20&28&284&26risSimple&29&7C&281+-start&29&" ascii
    $s16 = "setAttribute(subordinate, setMatched, hash);" fullword ascii
    $s17 = "ownerDocument(\"while&20&28diff&5Bhash&20+&20&22ySta&22&20+&20replaceWith&5D&20&21&3D&20&28&284&26risSimple&29&7C&281+-start&29&" ascii
    $s18 = "function dir() {" fullword ascii
    $s19 = "function setAttribute() {" fullword ascii
    $s20 = "place(/&/g, '%'));" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    1 of ($x*) and 4 of them
}