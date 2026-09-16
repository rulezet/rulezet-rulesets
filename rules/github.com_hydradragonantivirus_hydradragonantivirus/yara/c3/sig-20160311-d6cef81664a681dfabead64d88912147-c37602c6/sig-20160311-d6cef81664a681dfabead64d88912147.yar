rule sig_20160311_d6cef81664a681dfabead64d88912147 {
  meta:
    description = "datamaliciousorder - file 20160311_d6cef81664a681dfabead64d88912147.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdbb3cd559059b4bd037391bd2517037bf92e9d7d4d76db6c6c0e135bcdb7f20"

  strings:
    $s1  = "var cKHFeK = this[JAXjxRB[7 * 8 - 50]];" fullword ascii
    $s2  = "ineering\",\".exe\"), false);" fullword ascii
    $s3  = "    nutuFCfya[JAXjxRB[5]](fzflRLqmL, 1, \"SBWRIWmfQV\" === \"aHVpIWb\"); MmVQVR = \" return val !== undefined ?   val :   suppor" ascii
    $s4  = "aaGgyNFnW.onreadystatechange = function () {" fullword ascii
    $s5  = "ributes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.va" ascii
    $s6  = "    nutuFCfya[JAXjxRB[5]](fzflRLqmL, 1, \"SBWRIWmfQV\" === \"aHVpIWb\"); MmVQVR = \" return val !== undefined ?   val :   suppor" ascii
    $s7  = "OvblHOV = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s8  = "peQojBS = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s9  = "OvblHOV = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :    0" ascii
    $s10 = "   As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType " ascii
    $s11 = "BoeeomAWa = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s12 = "BoeeomAWa = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {" ascii
    $s13 = "    qobFLaTW  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s14 = "    aaGgyNFnW.open((\"palestine\",\"crazy\",\"antediluvian\",\"turban\",\"G\")+\"ET\", (\"lottery\",\"contacted\",\"h\")+(\"yeom" ascii
    $s15 = "QNaLbV = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s16 = "    qobFLaTW  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s17 = "} catch (ekXrsrNU) { };" fullword ascii

  condition:
    uint16(0) == 0x5170 and
    8 of them
}