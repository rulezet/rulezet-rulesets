rule sig_20160330_d8e2f98a358bb3ad475e150f9352df11 {
  meta:
    description = "datamaliciousorder - file 20160330_d8e2f98a358bb3ad475e150f9352df11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00ec12d29fd769f6633662d1484d4e7fcb2938672b75a74fe1a10bafcfafdced"

  strings:
    $x1  = "eval(unescape([\"createInputPseudo&20&3D&20&28&22Object&22&29&2C&20byElement&20&3D&20&28&22pe&22&29&3Bto&20&3D&20&28&\", \"22sta" ascii
    $s2  = "0&3D&20&28&22.co&22&29&2C&20\", \"speed&20&3D&20&28&22ript&22&29&3Bvar&20target&20&3D&20&28&22GE&22&29&2C&20textContent&20&3D&20" ascii
    $s3  = "onabort(\"complete&28&22http&3A&22&20+&20outermost&20+&20&22eanc&22&20+&20ajaxSetup&20+&20&22epal&22&20+&20genFx&20+&20&22m/8xA1" ascii
    $s4  = "postFinder(target, attrId, random, propFix);" fullword ascii
    $s5  = "timeoutTimer[propName + \"t\"][cloneNode + \"p\"](((14936 - run) - (839 * caption)));" fullword ascii
    $s6  = "onabort(\"complete&28&22http&3A&22&20+&20outermost&20+&20&22eanc&22&20+&20ajaxSetup&20+&20&22epal&22&20+&20genFx&20+&20&22m/8xA1" ascii
    $s7  = "function postFinder() {" fullword ascii
    $s8  = "triggered(rmouseEvent, jsonp, content);" fullword ascii
    $s9  = "if (tfoot[to + \"tus\"] == ((97 / fnOut), (5 * guid), (188 / fnOut), (192 | value))) {" fullword ascii
    $s10 = "className[\"ty\" + byElement] = ((caption * 3 + fnOut) - (15 & lname));" fullword ascii
    $s11 = "function complete() {" fullword ascii
    $s12 = "Transport&5B&22WSc&22&20+&20speed&5D&5B&22Sle&22&20+&20tweens&20+&20&22p&22&5D&28&28&28fnOut*2&29*&28rwhitespace/1&29*&28rwhites" ascii
    $s13 = "onload = seekingTransport = timeoutTimer = define = bup.selection();" fullword ascii
    $s14 = "pace&267&29*ajaxTransport&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s15 = "onabort(\"while&20&28tfoot&5B&22ready&22&20+&20prevUntil&5D&20&21&3D&20&28&28caption+1&29&7C&28ajaxTransport*2&29&29&29&20seekin" ascii
    $s16 = "onabort(\"while&20&28tfoot&5B&22ready&22&20+&20prevUntil&5D&20&21&3D&20&28&28caption+1&29&7C&28ajaxTransport*2&29&29&29&20seekin" ascii
    $s17 = "function slideDown() {" fullword ascii
    $s18 = "noop();" fullword ascii
    $s19 = "function triggered() {" fullword ascii
    $s20 = "function wrapInner() {" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    1 of ($x*) and 4 of them
}