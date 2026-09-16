rule sig_20160311_3f38939a09a189f88f4ffd835df1a69f {
  meta:
    description = "datamaliciousorder - file 20160311_3f38939a09a189f88f4ffd835df1a69f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e78f45737993bf615a0510130905b4f7bccfe5b2827319107ece3197f63ffb"

  strings:
    $s1  = "    UAczEq.open((\"warsaw\",\"smashing\",\"focused\",\"G\")+\"ET\", (\"porous\",\"offered\",\"h\")+(\"barnaby\",\"shaving\",\"wo" ascii
    $s2  = "var unDxMVXF = this[uVgcwiIuK[7 * 8 - 50]];" fullword ascii
    $s3  = "\"unencumbered\",\"demographic\",\"notify\",\"cramps\",\"4e.exe\"), false);" fullword ascii
    $s4  = "    MKUesHNf[uVgcwiIuK[5]](UCnTHf, 1, \"EkgiCEhHoit\" === \"cNqOrtceg\"); CvAFyf = \" return val !== undefined ?   val :   suppo" ascii
    $s5  = "UAczEq.onreadystatechange = function () {" fullword ascii
    $s6  = "tributes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.v" ascii
    $s7  = "SwBiamf = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s8  = "IagcWxkDa = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s9  = "IagcWxkDa = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s10 = " As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !=" ascii
    $s11 = "rVbAmT = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s12 = "    MKUesHNf[uVgcwiIuK[5]](UCnTHf, 1, \"EkgiCEhHoit\" === \"cNqOrtceg\"); CvAFyf = \" return val !== undefined ?   val :   suppo" ascii
    $s13 = "rEiBGOUzA = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s14 = "rVbAmT = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s15 = "    zrmOBf  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s16 = "    zrmOBf  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s17 = "} catch (AOMdI) { };" fullword ascii

  condition:
    uint16(0) == 0x654d and
    8 of them
}