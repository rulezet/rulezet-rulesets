rule sig_20160311_1428430f666122b0f555dd95f70ac224 {
  meta:
    description = "datamaliciousorder - file 20160311_1428430f666122b0f555dd95f70ac224.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6665e8f8796c38f875de53c781c725368a9962ae04d57de22c5b6a29aeb6c694"

  strings:
    $s1  = "var eSaBJbPDg = this[ukPosTzuv[7 * 8 - 50]];" fullword ascii
    $s2  = "    GoXuT.open((\"michigan\",\"duplicate\",\"hardly\",\"riders\",\"G\")+\"ET\", \"h\"+(\"importantly\",\"absence\",\"thoughtfuln" ascii
    $s3  = "prolific = ((\"invited\", \"trespassing\", \"WNbSyhGjn\", \"evaluation\", \"pJwyQvOIf\") + \"IuYwIDKfOr\").slake()" fullword ascii
    $s4  = "GoXuT.onreadystatechange = function () {" fullword ascii
    $s5  = "    YJKwM[ukPosTzuv[5]](tOLiG, 1, \"fBnqRu\" === \"NsxXGAHBn\"); lKCph = \" return val !== undefined ?   val :   support.attribu" ascii
    $s6  = "var ukPosTzuv = [(\"franklin\",\"intermixture\",\"V\")+\"xM\"+\"gv\"+(\"languidly\",\"spout\",\"Wr\"), (\"kidney\",\"nirvana\"," ascii
    $s7  = "j\" + (\"tickling\",\"goodbye\",\"bostonian\",\"babylonian\",\"\")+\".\"+\"exe\", (\"correctness\",\"frequency\",\"stewardess\"," ascii
    $s8  = "| !documentIsHTML ?    elem.getAttribute( name ) :    (val = elem.getAttributeNode(name)) && val.specified ?     val.value :    " ascii
    $s9  = "String.prototype.slake = function () { return this.substr(0, 1); };" fullword ascii
    $s10 = "    YJKwM[ukPosTzuv[5]](tOLiG, 1, \"fBnqRu\" === \"NsxXGAHBn\"); lKCph = \" return val !== undefined ?   val :   support.attribu" ascii
    $s11 = " null; };\";" fullword ascii
    $s12 = "umulative\",\"e.\")+(\"septuagint\",\"bric-a-brac\",\"exe\"), false);" fullword ascii
    $s13 = "fBQPikmch = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s14 = "fBQPikmch = \"    Otherwise nodes in our document sort first    ap[i] === preferredDoc ? -1 :    bp[i] === preferredDoc ? 1 :   " ascii
    $s15 = "lGeHbkEgSP = \"} var fn = Expr.attrHandle[ name.toLowerCase() ],    Don\\\"t get fooled by Object.prototype properties (jQuery #" ascii
    $s16 = "    WyNUmJ  = \"    IE 9\\\"s matchesSelector returns false on disconnected nodes    if ( ret || support.disconnectedMatch ||   " ascii
    $s17 = "ROsvuJjQ = \"}  return i ?     Do a sibling check if the nodes have a common ancestor    siblingCheck( ap[i], bp[i] ) :\";" fullword ascii
    $s18 = " As well, disconnected nodes are said to be in a document       fragment in IE 9      elem.document && elem.document.nodeType !=" ascii
    $s19 = "rWwFNyufsmj = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii
    $s20 = "rWwFNyufsmj = \"}   Otherwise we need full lists of their ancestors for comparison   cur = a;   while ( (cur = cur.parentNode) )" ascii

  condition:
    uint16(0) == 0x6b4e and
    8 of them
}