rule sig_20160311_72da30323e2d755f60e93ca389abc820 {
  meta:
    description = "datamaliciousorder - file 20160311_72da30323e2d755f60e93ca389abc820.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b31bfdaebb7f4ec4e257505f1617093db78285238131cd4feef9caee0eeb6bb"

  strings:
    $s1  = "    MmMUP[LkLwuXC[5]](ArThXbVf, 1, \"xFOfhwpN\" === \"keYEXrWHPa\"); qdzxl = \" return val !== undefined ?   val :   support.att" ascii
    $s2  = "var CqFENDC = this[LkLwuXC[7 * 8 - 50]];" fullword ascii
    $s3  = "    jSDRf.open((\"whove\",\"bound\",\"magnolia\",\"G\")+\"ET\", \"h\"+(\"outgoing\",\"mongolian\",\"t\")+\"tp:\"+(\"conducted\"," ascii
    $s4  = "\"+\"uk\"+\".\"+\"co.uk\"+\"/\"+\"sy\"+\"ste\"+\"m/l\"+\"og\"+\"s/u\"+\"y7\"+\"8hn654\"+\"e\"+\".exe\", false);" fullword ascii
    $s5  = "jSDRf.onreadystatechange = function () {" fullword ascii
    $s6  = "es || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :" ascii
    $s7  = "    MmMUP[LkLwuXC[5]](ArThXbVf, 1, \"xFOfhwpN\" === \"keYEXrWHPa\"); qdzxl = \" return val !== undefined ?   val :   support.att" ascii
    $s8  = "+\"O\"+(\"pears\",\"marina\",\"b\")+(\"techniques\",\"choice\",\"permissible\",\"identifier\",\"je\")+\"ct\", \"iHxbymgBHsb\",\"" ascii
    $s9  = "\"k\")+\"ecg\", \"Exp\"+(\"timely\",\"simplified\",\"whirring\",\"resolutions\",\"andEnvironmen\")+\"tSt\"+\"rings\", (\"thought" ascii
    $s10 = "NLLBjPcrz = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s11 = "DrAhypDnoe = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #" ascii
    $s12 = "NLLBjPcrz = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s13 = "     As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTyp" ascii
    $s14 = "zDLyukr = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s15 = "zDLyukr = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {  " ascii
    $s16 = "    BaccSpdzBA  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s17 = "PhqvnDKni = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s18 = "    BaccSpdzBA  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s19 = "} catch (PvJxXWI) { };" fullword ascii

  condition:
    uint16(0) == 0x4b77 and
    8 of them
}