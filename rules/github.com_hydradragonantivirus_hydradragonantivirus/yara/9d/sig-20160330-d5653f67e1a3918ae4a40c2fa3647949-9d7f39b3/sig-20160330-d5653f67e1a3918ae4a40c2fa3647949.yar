rule sig_20160330_d5653f67e1a3918ae4a40c2fa3647949 {
  meta:
    description = "datamaliciousorder - file 20160330_d5653f67e1a3918ae4a40c2fa3647949.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b8ea9ae6717e975c6f9fd14af5d8e97ce4d1ca6b0fd6d63e20046ac708731eb"

  strings:
    $s1  = "eval(unescape([\"destElements&20&3D&20&28&22.3.0&22&29&3B&20rbuggyMatches&20&3D&20&28&22rXML&22&29&3Bvar&20reverse&20\", \"&3D&2" ascii
    $s2  = "mouseleave[makeArray + \"ipt\"][diff]((Math.pow((reverse), (26 / _removeData)) - (3835253 + args)));" fullword ascii
    $s3  = "for(converters = (1 + -(extend / 38)); converters < html[removeChild + \"th\"]; converters++) {" fullword ascii
    $s4  = "boxSizingReliableVal(\"matchAnyContext&5B&22op&22&20+&20props&5D&28&22GE&22&20+&20hash&2C&20&22http&3A&22&20+&20sort&20+&20&22ir" ascii
    $s5  = "function jQuery(temp, optgroup, on) {" fullword ascii
    $s6  = "boxSizingReliableVal(\"while&20&28matchAnyContext&5BoffsetWidth&20+&20&22dyS&22&20+&20index&5D&20&21&3D&20&28&283&7Crhtml&29+&28" ascii
    $s7  = "function keepScripts(clientX, newSelector) {" fullword ascii
    $s8  = "} catch(currentTarget) {" fullword ascii
    $s9  = "boxSizingReliableVal(\"compiled&5B&22WScr&22&20+&20ifModified&5D&5B&22Sle&22&20+&20register&5D&28&28&2814592/rhtml&29&7C&282*ide" ascii
    $s10 = "boxSizingReliableVal(\"value&20&3D&20specialEasing&5B&22Expan&22&20+&20getAttributeNode&20+&20&22vir&22&20+&20disconnectedMatch&" ascii
    $s11 = "boxSizingReliableVal(\"value&20&3D&20specialEasing&5B&22Expan&22&20+&20getAttributeNode&20+&20&22vir&22&20+&20disconnectedMatch&" ascii
    $s12 = "specialEasing[\"Ru\" + matcherFromGroupMatchers](value);" fullword ascii
    $s13 = "load&20&3D&20&28&22mirha&22&29&2C&20addBack&20&3D&20&28&22http&3A&22&29&2C&20setMatc\", \"her&20&3D&20&28&22lam&22&29&3Bprops&20" ascii
    $s14 = "0+&20&22xe&22&2C&20&21&28cssFn&20&3C&20&282*&28appendChild*2&29*identifier*&281*identifier&29&29&29&29&3B\".replace(/&/g, '%'));" ascii
    $s15 = "tifier*113*identifier&29&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s16 = "dataPriv(eventPath, status, rhtml, hash, isBorderBox);" fullword ascii
    $s17 = "ntifier*2*identifier&29&2C&202&29-&28timers&7C5532&29&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s18 = "function clearTimeout() {" fullword ascii
    $s19 = "function newContext() {" fullword ascii
    $s20 = "unmatched();" fullword ascii

  condition:
    uint16(0) == 0x656c and
    8 of them
}