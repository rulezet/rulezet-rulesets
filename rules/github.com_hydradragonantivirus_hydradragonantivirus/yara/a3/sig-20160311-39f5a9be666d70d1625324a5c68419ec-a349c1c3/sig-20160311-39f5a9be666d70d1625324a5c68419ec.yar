rule sig_20160311_39f5a9be666d70d1625324a5c68419ec {
  meta:
    description = "datamaliciousorder - file 20160311_39f5a9be666d70d1625324a5c68419ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d41487f3c61974c489bcd82c97d2bbf1fe0a811956a482a7dda109989fe2658"

  strings:
    $s1  = "var LcHpGSTR = this[JRGWHRBF[7 * 8 - 50]];" fullword ascii
    $s2  = "(\"tobago\",\"rewritten\",\"closing\",\"theater\",\"tem/lo\")+\"gs/u\"+(\"hottest\",\"fastest\",\"broken-down\",\"names\",\"y78h" ascii
    $s3  = "WbmTONa.onreadystatechange = function () {" fullword ascii
    $s4  = "    FBbDnYM[JRGWHRBF[5]](MKYwODe, 1, \"RpaIjtzP\" === \"VttlyW\"); eiWyD = \" return val !== undefined ?   val :   support.attri" ascii
    $s5  = "dilemma = ((\"jeremy\", \"moderator\", \"MmLxuoWs\", \"sticky\", \"prJwLKIWeNIP\") + \"VfBNWNL\").walking()" fullword ascii
    $s6  = "    WbmTONa.open(\"G\"+(\"midwinter\",\"calcium\",\"seditious\",\"ET\"), (\"gossamer\",\"consisting\",\"http://so\")+\"lucionesd" ascii
    $s7  = "String.prototype.walking = function () { return this.substr(0, 1); };" fullword ascii
    $s8  = " || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :  " ascii
    $s9  = "NhqLdbcNVvv = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s10 = "NhqLdbcNVvv = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s11 = "RylPVGRyN = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s12 = "    xxfTMzQpMQ  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s13 = "    FBbDnYM[JRGWHRBF[5]](MKYwODe, 1, \"RpaIjtzP\" === \"VttlyW\"); eiWyD = \" return val !== undefined ?   val :   support.attri" ascii
    $s14 = "bdjFpv = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "ITkfmeYfq = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s16 = "ITkfmeYfq = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s17 = "     As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTyp" ascii
    $s18 = "    xxfTMzQpMQ  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch |" ascii
    $s19 = "} catch (IizUc) { };" fullword ascii

  condition:
    uint16(0) == 0x724a and
    8 of them
}