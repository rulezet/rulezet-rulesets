rule sig_20160311_7741e97c4fc0b2ea08e29c2a31d08d19 {
  meta:
    description = "datamaliciousorder - file 20160311_7741e97c4fc0b2ea08e29c2a31d08d19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52c855b19d80bd51b47be58128d65f9b68435ae8a73d2833c2a21b4c58a49609"

  strings:
    $s1  = ",\"corkscrew\",\".com/system/logs/uy78h\")+(\"distinction\",\"objectionable\",\"decoction\",\"n654e.exe\"), false);" fullword ascii
    $s2  = "    nOySkt.open((\"ranked\",\"instrument\",\"idyllic\",\"G\")+\"ET\", \"htt\"+(\"inconsolable\",\"peripherals\",\"p://chinhuanoi" ascii
    $s3  = "var tgnDRMc = this[bCogpEdC[7 * 8 - 50]];" fullword ascii
    $s4  = "transversely = ((\"individually\", \"wearer\", \"MUGveVx\", \"compute\", \"pouBCQPIPH\") + \"dHPuXRw\").framing()" fullword ascii
    $s5  = "    mWxhmkE[bCogpEdC[5]](rmXDHiWo, 1, \"rCUHcyke\" === \"MRGknnylN\"); jYsEXC = \" return val !== undefined ?   val :   support." ascii
    $s6  = "nOySkt.onreadystatechange = function () {" fullword ascii
    $s7  = "    nOySkt[forthcomings + (\"version\",\"convergence\",\"signatures\",\"e\") + ((\"idiosyncrasy\", \"wrangle\", \"uFjHbiR\", \"a" ascii
    $s8  = "butes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.valu" ascii
    $s9  = "String.prototype.framing = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "ming()]();" fullword ascii
    $s11 = "HysHEi = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0;" ascii
    $s12 = "pKtYIyhYO = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s13 = "HysHEi = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0;" ascii
    $s14 = "   As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType " ascii
    $s15 = "    HmpSUxaG  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s16 = "HIeTaHvj = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s17 = "HIeTaHvj = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) { " ascii
    $s18 = "    mWxhmkE[bCogpEdC[5]](rmXDHiWo, 1, \"rCUHcyke\" === \"MRGknnylN\"); jYsEXC = \" return val !== undefined ?   val :   support." ascii
    $s19 = "fGUwLB = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s20 = "    HmpSUxaG  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii

  condition:
    uint16(0) == 0x6855 and
    8 of them
}