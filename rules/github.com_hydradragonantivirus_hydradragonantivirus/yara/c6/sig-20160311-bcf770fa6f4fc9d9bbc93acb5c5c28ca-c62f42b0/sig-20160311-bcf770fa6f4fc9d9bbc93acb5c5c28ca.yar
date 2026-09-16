rule sig_20160311_bcf770fa6f4fc9d9bbc93acb5c5c28ca {
  meta:
    description = "datamaliciousorder - file 20160311_bcf770fa6f4fc9d9bbc93acb5c5c28ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4bd3468021fab2351c553fedc126613f9023e8272f126fae0a05d96c11a6724"

  strings:
    $s1  = "var SlFnLGt = this[vBuREciw[7 * 8 - 50]];" fullword ascii
    $s2  = "tfQir.onreadystatechange = function () {" fullword ascii
    $s3  = "    HPnHDUuB[vBuREciw[5]](wndhVqFx, 1, \"bfsDOeDFf\" === \"ujDlkr\"); oTyyzg = \" return val !== undefined ?   val :   support.a" ascii
    $s4  = "utes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value" ascii
    $s5  = "    tfQir.open((\"mustard\",\"egotistical\",\"G\")+\"ET\", \"ht\"+\"t\"+(\"symphony\",\"planetary\",\"conglomerate\",\"nutshell" ascii
    $s6  = "    tfQir.open((\"mustard\",\"egotistical\",\"G\")+\"ET\", \"ht\"+\"t\"+(\"symphony\",\"planetary\",\"conglomerate\",\"nutshell" ascii
    $s7  = "var vBuREciw = [(\"acceded\",\"amongst\",\"conservation\",\"jkC\")+(\"genealogical\",\"scared\",\"signature\",\"xBC\")+\"Q\"+\"y" ascii
    $s8  = "\"tunnel\",\"unless\",\"n654\")+\"e\"+\".\"+\"e\"+\"xe\", false);" fullword ascii
    $s9  = "NXidFpsvTwP = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery " ascii
    $s10 = "jyaIjAUcmMp = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s11 = "jyaIjAUcmMp = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 : " ascii
    $s12 = "      As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeTy" ascii
    $s13 = "    HPnHDUuB[vBuREciw[5]](wndhVqFx, 1, \"bfsDOeDFf\" === \"ujDlkr\"); oTyyzg = \" return val !== undefined ?   val :   support.a" ascii
    $s14 = "zhLiJRPAzhS = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s15 = "zhLiJRPAzhS = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s16 = "BWSVKxzaT = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s17 = "    HhMAxauXUwz  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s18 = "    HhMAxauXUwz  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch " ascii
    $s19 = "} catch (xjLtVUaPI) { };" fullword ascii

  condition:
    uint16(0) == 0x7a67 and
    8 of them
}