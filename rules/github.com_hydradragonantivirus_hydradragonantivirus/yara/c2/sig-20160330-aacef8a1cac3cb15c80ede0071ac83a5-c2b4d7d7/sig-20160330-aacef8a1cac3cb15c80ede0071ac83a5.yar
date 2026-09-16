rule sig_20160330_aacef8a1cac3cb15c80ede0071ac83a5 {
  meta:
    description = "datamaliciousorder - file 20160330_aacef8a1cac3cb15c80ede0071ac83a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44dea7c7dcb35fe5aad77afbb0f592a24c8c80b169927cadaefc7b8103e42179"

  strings:
    $s1  = "eval(unescape([\"var&20nodeValue&20&3D&20&28&22n&22&29&2C&20hasContent&20&3D&20&28&22l2.&22&29&2C&20deep&20&3D&20&28&\", \"22op&" ascii
    $s2  = "if(rscriptType[setAttribute + \"atu\" + optSelected] == ((scrollLeft | 4) * (chainable / 20) * (deepDataAndEvents / 9) * (last) " ascii
    $s3  = "defaultValue(\"height&28globalEval&20+&20&22//b&22&20+&20tokenize&20+&20&22nip&22&20+&20selection&20+&20&22.com&22&20+&20clearCl" ascii
    $s4  = "defaultValue(\"height&28globalEval&20+&20&22//b&22&20+&20tokenize&20+&20&22nip&22&20+&20selection&20+&20&22.com&22&20+&20clearCl" ascii
    $s5  = "if(rscriptType[setAttribute + \"atu\" + optSelected] == ((scrollLeft | 4) * (chainable / 20) * (deepDataAndEvents / 9) * (last) " ascii
    $s6  = "postFilter[\"op\" + test]();" fullword ascii
    $s7  = "defaultValue(\"while&20&28rscriptType&5B&22read&22&20+&20when&20+&20&22te&22&5D&20&21&3D&20&28&2841-elemLang&29&26&287&26setPosi" ascii
    $s8  = "postFilter[\"ty\" + reset + \"e\"] = (1 * (v & 1));" fullword ascii
    $s9  = "(51 - blur))) {" fullword ascii
    $s10 = "function serialize(restoreScript, curPosition, n) {" fullword ascii
    $s11 = "defaultValue(\"while&20&28rscriptType&5B&22read&22&20+&20when&20+&20&22te&22&5D&20&21&3D&20&28&2841-elemLang&29&26&287&26setPosi" ascii
    $s12 = "function firstChild(uniqueID, getResponseHeader, rneedsContext) {" fullword ascii
    $s13 = "postFilter[location + \"od\" + origCount] = ((92, fadeToggle, 1) * (text));" fullword ascii
    $s14 = "left(postFinder, setAttribute);" fullword ascii
    $s15 = "function node(disableScript, compilerCache) {" fullword ascii
    $s16 = "turn&20getStyles&3B&7D&2C&20&22azarga&22&29&3Bchainable&20&3D&20&28100&29&3B&3B\"].join(\"\").replace(/&/g, '%')));" fullword ascii
    $s17 = "firstChild(setup, th, postFinder);" fullword ascii
    $s18 = "function getClass(seekingTransport) {" fullword ascii
    $s19 = "7Ccollection&29&2C&28Math.pow&2868&2C&20last&29-4543&29&2C&28scrollLeft*2*scrollLeft*5*scrollLeft*2*last&29&29&29&3B\".replace(/" ascii
    $s20 = "function _data(pushStack, overflowY, dirrunsUnique) {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}