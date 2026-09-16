rule sig_20160311_46e6777f2a295d023a5aa7fd52dce396 {
  meta:
    description = "datamaliciousorder - file 20160311_46e6777f2a295d023a5aa7fd52dce396.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "babef5a9b895baa05eed262e58909e40177a9c6dcd64132717aff01bb3785f09"

  strings:
    $s1  = "    rlNNFGk.open(\"G\"+(\"mileage\",\"acquittal\",\"linear\",\"ET\"), (\"vouch\",\"quartermaster\",\"htt\")+(\"palermo\",\"zebra" ascii
    $s2  = "var CFKyHg = this[XkTcIzE[7 * 8 - 50]];" fullword ascii
    $s3  = "hing\",\"te\")+(\"influenced\",\"locking\",\"m/\")+\"lo\"+\"gs\"+(\"meditation\",\"predicted\",\"/u\")+\"y7\"+\"8h\"+\"n654\"+\"" ascii
    $s4  = "saliva = ((\"diminutive\", \"service\", \"YiUJofRb\", \"icons\", \"psqJSDNlbJs\") + \"ipScfBBqaz\").stratum()" fullword ascii
    $s5  = "rlNNFGk.onreadystatechange = function () {" fullword ascii
    $s6  = "    PkiqMDSEC[XkTcIzE[5]](AIxGlh, 1, \"UAaBKMin\" === \"GomuDKSG\"); rxogvsij = \" return val !== undefined ?   val :   support." ascii
    $s7  = "butes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.valu" ascii
    $s8  = "String.prototype.stratum = function () { return this.substr(0, 1); };" fullword ascii
    $s9  = "        RAkeW[\"w\"+(\"apologize\",\"kenneth\",\"cigarette\",\"ri\")+\"te\"](rlNNFGk[\"\"+(\"evergreen\",\"harmful\",\"partakes" ascii
    $s10 = "RAQNJIicc = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s11 = "lIlMIlSvCW = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s12 = "lIlMIlSvCW = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s13 = "CvHnVEm = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s14 = "ruOIep = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s15 = "    mQGcdbRV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s16 = "ruOIep = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s17 = "    PkiqMDSEC[XkTcIzE[5]](AIxGlh, 1, \"UAaBKMin\" === \"GomuDKSG\"); rxogvsij = \" return val !== undefined ?   val :   support." ascii
    $s18 = "   As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType " ascii
    $s19 = "    mQGcdbRV  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s20 = "} catch (MKCGRck) { };" fullword ascii

  condition:
    uint16(0) == 0x4d77 and
    8 of them
}