rule sig_20160330_59c7e8e2a6b883b0c00ea0de4f693987 {
  meta:
    description = "datamaliciousorder - file 20160330_59c7e8e2a6b883b0c00ea0de4f693987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d2148d69216d198aa72599ce621fdb2cee1abfe9cf0f8fa566fe1b5253c75d8"

  strings:
    $s1  = "function visibility(scripts, contentDocument) {" fullword ascii
    $s2  = "tabIndex[getResponseHeader + \"y\" + oldCache + \"e\"] = (1 | original);" fullword ascii
    $s3  = "    result(\"grep&20&3D&20fixInput&5B&22Expand&22&20+&20removeChild&20+&20&22ironm&22&20+&20getById&20+&20&22Strin&22&20+&20stat" ascii
    $s4  = "    for (value = ((1 * original) * (0 | hasContent)); value < combinator[\"leng\" + tbody]; value++) {" fullword ascii
    $s5  = "    if (noBubble[\"statu\" + props] == (5 * (animated / 21) * invert * (23 - dirruns) * (1 * invert))) {" fullword ascii
    $s6  = "    result(\"noBubble&20&3D&20uid&5B&22WSc&22&20+&20postFilter&20+&20&22t&22&5D&5Brelated&20+&20&22teObj&22&20+&20dataUser&5D&28" ascii
    $s7  = "mage&20+&20&222.XML&22&20+&20rbuggyQSA&20+&20&22.0&22&2C&20image&20+&20&222.Serv&22&20+&20onreadystatechange&20+&20&22LHT&22&20+" ascii
    $s8  = "C91&2Coriginal&29+&281*hasContent&29&29&20&3D&3D&20&28&281*original&29*&281+hasContent&29&29&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s9  = "function fns(code, extend, version) {" fullword ascii
    $s10 = "function configurable(lock, tweener, split) {" fullword ascii
    $s11 = "    result(\"noBubble&20&3D&20uid&5B&22WSc&22&20+&20postFilter&20+&20&22t&22&5D&5Brelated&20+&20&22teObj&22&20+&20dataUser&5D&28" ascii
    $s12 = "    result(\"combinator&20&3D&20&5Bimage&20+&20&222.Se&22&20+&20genFx&20+&20&22XMLHTT&22&20+&20pointerenter&20+&20&22.0&22&2C&20" ascii
    $s13 = "        tabIndex[\"Save\" + isBorderBox + \"ile\"](grep, ((1 * invert)));" fullword ascii
    $s14 = "    result(\"tabIndex&20&3D&20uid&5Bm&20+&20&22t&22&5D&5Bunmatched&20+&20&22ateObj&22&20+&20dataUser&5D&28&22ADO&22&20+&20open&2" ascii
    $s15 = "    result(\"tabIndex&20&3D&20uid&5Bm&20+&20&22t&22&5D&5Bunmatched&20+&20&22ateObj&22&20+&20dataUser&5D&28&22ADO&22&20+&20open&2" ascii
    $s16 = "function createHTMLDocument() {" fullword ascii
    $s17 = "function elementMatcher() {" fullword ascii
    $s18 = "function params() {" fullword ascii
    $s19 = "originalProperties(animated, selectors);" fullword ascii
    $s20 = "createOptions(unmatched, tbody, event, structure, msMatchesSelector);" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}