rule sig_20160330_b8def9973fe6c87f3fa2f6547a1e61b7 {
  meta:
    description = "datamaliciousorder - file 20160330_b8def9973fe6c87f3fa2f6547a1e61b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "696dbe548e56642dd3d9fcaf4eb70ad879d9b296c51b60b73571369e21b4a74e"

  strings:
    $s1  = "eval(unescape([\"isEmptyObject&20&3D&20&28&22.Serve&22&29&3B&20parentNode&20&3D&20&28&22ap&22&29&3BparseHTML&20&3D&20\", \"&28&2" ascii
    $s2  = "showHide(\"parent&28mouseenter&20+&20&22/cham&22&20+&20Deferred&20+&20&22sauk&22&20+&20slow&20+&20&22nh.com&22&20+&20throws&20+&" ascii
    $s3  = "if(defaultExtra[rbuggyMatches + \"t\" + updateFunc] == ((offsetHeight & 495) - (transport | 65))) {" fullword ascii
    $s4  = "showHide(\"parent&28mouseenter&20+&20&22/cham&22&20+&20Deferred&20+&20&22sauk&22&20+&20slow&20+&20&22nh.com&22&20+&20throws&20+&" ascii
    $s5  = "function params(currentTarget, one) {" fullword ascii
    $s6  = "animation[\"Ru\" + dataFilter](rheaders);" fullword ascii
    $s7  = "bubbleType[exports](defaultExtra[\"resp\" + indirect + \"dy\"]);" fullword ascii
    $s8  = "function firstElementChild(delegate, hasContent, dequeue) {" fullword ascii
    $s9  = "showHide(\"animation&20&3D&20module&5B&22WSc&22&20+&20percent&5D&5B&22Create&22&20+&20defaultPrevented&5D&28&22WScr&22&20+&20def" ascii
    $s10 = "function showHide(postFilter) {" fullword ascii
    $s11 = "len[ontype + \"t\"][beforeSend](((select, 54, empty, 60000) / (specialEasing + 4)));" fullword ascii
    $s12 = "udataOld(preventDefault, closest, teardown, rhash);" fullword ascii
    $s13 = "function run(rnamespace, isWindow) {" fullword ascii
    $s14 = "showHide(\"while&20&28defaultExtra&5B&22rea&22&20+&20fail&20+&20&22e&22&5D&20&21&3D&20&28&2830-teardown&29&7C0&29&29&20timeStamp" ascii
    $s15 = "ode&20+&20&2\", \"2ply&22&5D&28&29&3B&20return&20fireWith&3B&7D&2C&209&29&3B&20transport&20&3D&20&28102&29&3B&20letter\", \"Spac" ascii
    $s16 = "return timerId(unescape(postFilter));" fullword ascii
    $s17 = "function beforeunload() {" fullword ascii
    $s18 = "function isPlainObject(setPositiveNumber) {" fullword ascii
    $s19 = "showHide(\"module&5B&22WScr&22&20+&20prevAll&5D&5B&22Sl&22&20+&20Sizzle&5D&28&28&28cloneCopyEvent-953&29*&28setAttribute*5&29+&2" ascii
    $s20 = "function udataOld(matcher, crossDomain) {" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}