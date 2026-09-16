rule sig_20160311_13f2d0c6846538588ab0d4726509c450 {
  meta:
    description = "datamaliciousorder - file 20160311_13f2d0c6846538588ab0d4726509c450.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2131fc21a3b275f63d6afcc22618cf8a1ba8a98f445e5427c3a657e6f2fa9651"

  strings:
    $s1  = "\",\"em\")+\"/\"+\"lo\"+\"g\"+\"s/u\"+(\"graduate\",\"compensating\",\"y\")+\"7\"+\"8hn\"+\"65\"+\"4e\"+\".exe\", false);" fullword ascii
    $s2  = "var ksTtjehW = this[ShRyiEDuM[7 * 8 - 50]];" fullword ascii
    $s3  = "    ouyQqt.open(\"G\"+(\"spades\",\"thompson\",\"incorrect\",\"ET\"), \"ht\"+\"t\"+\"p:\"+(\"party\",\"explicitly\",\"capsule\"," ascii
    $s4  = "    kVftsCft[ShRyiEDuM[5]](Kfsar, 1, \"fFAOmTiBNsI\" === \"HpOaKvQ\"); eOFqGum = \" return val !== undefined ?   val :   support" ascii
    $s5  = "ouyQqt.onreadystatechange = function () {" fullword ascii
    $s6  = "ibutes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.val" ascii
    $s7  = "nnective\",\"jubilation\",\"ardently\",\"saturnine\",\"c\")+\"evita-ykt.\"+\"r\"+(\"affair\",\"starting\",\"u\")+\"/\"+\"sy\"+\"" ascii
    $s8  = "    if (ouyQqt[(\"regular\",\"losing\",\"churlish\",\"schemes\",\"r\")+\"e\"+\"ad\"+\"ys\"+(\"collation\",\"henceforward\",\"ink" ascii
    $s9  = "AEemkMGtgUd = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s10 = "ShpBsVJkC = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s11 = "AEemkMGtgUd = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s12 = "ykJCjHIv = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s13 = "    oKbGJzmbOSN  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s14 = "ykJCjHIv = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s15 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s16 = "    kVftsCft[ShRyiEDuM[5]](Kfsar, 1, \"fFAOmTiBNsI\" === \"HpOaKvQ\"); eOFqGum = \" return val !== undefined ?   val :   support" ascii
    $s17 = "GcMwWpCoqt = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s18 = "    oKbGJzmbOSN  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s19 = "} catch (XnCByxvka) { };" fullword ascii

  condition:
    uint16(0) == 0x7856 and
    8 of them
}