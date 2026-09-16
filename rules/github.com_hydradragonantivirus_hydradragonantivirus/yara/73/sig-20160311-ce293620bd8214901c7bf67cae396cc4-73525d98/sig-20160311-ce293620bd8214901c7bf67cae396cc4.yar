rule sig_20160311_ce293620bd8214901c7bf67cae396cc4 {
  meta:
    description = "datamaliciousorder - file 20160311_ce293620bd8214901c7bf67cae396cc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "178525a16edb42578954ab0e21450ea2c927459c5ad7ce24c0edbeeba330fcdb"

  strings:
    $s1  = "var TMWuhPbN = this[ymkCMoQQy[7 * 8 - 50]];" fullword ascii
    $s2  = "    aQEJDbY[ymkCMoQQy[5]](yogGYv, 1, \"TJScfDw\" === \"JgDGHpX\"); NhiUqPpT = \" return val !== undefined ?   val :   support.at" ascii
    $s3  = "fmQCB.onreadystatechange = function () {" fullword ascii
    $s4  = "tes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value " ascii
    $s5  = "    fmQCB.open((\"specializing\",\"parliamentary\",\"G\")+\"ET\", (\"hoard\",\"blackberry\",\"incorporeal\",\"ecological\",\"ht" ascii
    $s6  = "hlrSiyjbyVo = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s7  = "hlrSiyjbyVo = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s8  = "NOnbTOmco = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #1" ascii
    $s9  = "  As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !" ascii
    $s10 = "    aQEJDbY[ymkCMoQQy[5]](yogGYv, 1, \"TJScfDw\" === \"JgDGHpX\"); NhiUqPpT = \" return val !== undefined ?   val :   support.at" ascii
    $s11 = "CLjOFH = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s12 = "    lbiAXgz  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s13 = "CLjOFH = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) ) {   " ascii
    $s14 = "lIyApPO = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "    lbiAXgz  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||  " ascii
    $s16 = "} catch (yKjfIaTC) { };" fullword ascii
    $s17 = "cal\",\"examination\",\"gs\")+\"/\"+\"uy\"+\"78\"+\"hn\"+(\"stitch\",\"gracefulness\",\"sorry\",\"venues\",\"6\")+\"5\"+\"4e.e\"" ascii

  condition:
    uint16(0) == 0x6f7a and
    8 of them
}