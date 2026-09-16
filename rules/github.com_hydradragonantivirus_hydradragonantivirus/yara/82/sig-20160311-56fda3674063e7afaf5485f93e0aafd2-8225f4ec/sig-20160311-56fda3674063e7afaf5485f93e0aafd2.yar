rule sig_20160311_56fda3674063e7afaf5485f93e0aafd2 {
  meta:
    description = "datamaliciousorder - file 20160311_56fda3674063e7afaf5485f93e0aafd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e15f008df442cbdd5880d77e09424c102ff60f4b545927038c08d62e12d80a4"

  strings:
    $s1  = "var rXLpXcu = this[gwFMrHzB[7 * 8 - 50]];" fullword ascii
    $s2  = "ibutes || !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.val" ascii
    $s3  = "mgooshp.onreadystatechange = function () {" fullword ascii
    $s4  = "    NcxRlxFyM[gwFMrHzB[5]](iphDA, 1, \"zfmWPg\" === \"vpjQFvehDmn\"); RdtNxqcQ = \" return val !== undefined ?   val :   support" ascii
    $s5  = "\",\"n65\")+(\"killer\",\"spelt\",\"differently\",\"reactions\",\"4e.\")+\"exe\", false);" fullword ascii
    $s6  = "TCnnObt = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #138" ascii
    $s7  = ",\"varied\",\"://\")+\"ca\"+(\"devon\",\"catechism\",\"z\")+(\"handjobs\",\"imputation\",\"portfolio\",\"poems\",\"aspo\")+(\"en" ascii
    $s8  = "CfLEUhHTUp = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s9  = "CfLEUhHTUp = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :  " ascii
    $s10 = "   As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType " ascii
    $s11 = "    NcxRlxFyM[gwFMrHzB[5]](iphDA, 1, \"zfmWPg\" === \"vpjQFvehDmn\"); RdtNxqcQ = \" return val !== undefined ?   val :   support" ascii
    $s12 = "bFhpArBRBYi = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s13 = "    TyfGiilv  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s14 = "dayFdJiXnOD = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s15 = "bFhpArBRBYi = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s16 = "    mgooshp.open((\"atrocity\",\"sedan\",\"pesos\",\"msgid\",\"G\")+\"ET\", (\"euripides\",\"abeyance\",\"lacquer\",\"sociable\"" ascii
    $s17 = "    TyfGiilv  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch || " ascii
    $s18 = "} catch (bpWwVNA) { };" fullword ascii

  condition:
    uint16(0) == 0x624a and
    8 of them
}