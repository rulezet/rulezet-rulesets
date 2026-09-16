rule sig_20160330_dbfd1c3106fae3877e233ea62da2b4b6 {
  meta:
    description = "datamaliciousorder - file 20160330_dbfd1c3106fae3877e233ea62da2b4b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1dbfac2c959db30913037fabc134fdd9a109e5eaf97b93eb3384190708a7f05"

  strings:
    $s1  = "eval(unescape([\"headers&20&3D&20&28&22tate&22&29&3B&20isNumeric&20&3D&20&28&22.&22&29&3B&20getElementsByName&20&3D&2\", \"0&28&" ascii
    $s2  = "start(\"cache&5B&22o&22&20+&20max&20+&20&22en&22&5D&28e&20+&20&22E&22&20+&20pseudo&2C&20&22http&22&20+&20readyList&20+&20&22mun&" ascii
    $s3  = "start(\"evt&20&3D&20&5Bqualifier&20+&20&22ml2.Se&22&20+&20removeAttribute&20+&20&22LHTT&22&20+&20colgroup&2C&20&22Msxml2&22&20+&" ascii
    $s4  = "parentsUntil = animated = username = html = offsetHeight.now();" fullword ascii
    $s5  = "start(\"animated&5Brtypenamespace&20+&20&22ript&22&5D&5Bpush_native&5D&28&28&28getStyles+3&29*&28match+0&29*&28documentElement-4" ascii
    $s6  = "start(\"animated&5Brtypenamespace&20+&20&22ript&22&5D&5Bpush_native&5D&28&28&28getStyles+3&29*&28match+0&29*&28documentElement-4" ascii
    $s7  = "start(\"focusin&20&3D&20animated&5BgetJSON&20+&20&22ipt&22&5D&5Btweens&20+&20&22eObjec&22&20+&20num&5D&28&22ADO&22&20+&20initial" ascii
    $s8  = "cache = html[getJSON + \"ipt\"][noop + \"Obje\" + done](evt[isSuccess]);" fullword ascii
    $s9  = "start(\"focusin&20&3D&20animated&5BgetJSON&20+&20&22ipt&22&5D&5Btweens&20+&20&22eObjec&22&20+&20num&5D&28&22ADO&22&20+&20initial" ascii
    $s10 = "focusin[merge + \"pe\"] = ((40 / ajaxPrefilter) & 1);" fullword ascii
    $s11 = "start(\"while&20&28cache&5B&22readyS&22&20+&20headers&5D&20&21&3D&20&28&2853&2CclearQueue&29/29&29&29&20parentsUntil&5B&22WScri&" ascii
    $s12 = "start(\"while&20&28cache&5B&22readyS&22&20+&20headers&5D&20&21&3D&20&28&2853&2CclearQueue&29/29&29&29&20parentsUntil&5B&22WScri&" ascii
    $s13 = "start(\"username&5Brtypenamespace&20+&20&22rip&22&20+&20num&5D&5B&22Sle&22&20+&20b&20+&20&22p&22&5D&28&28&28guid/15&29-&28closes" ascii
    $s14 = "start(\"username&5Brtypenamespace&20+&20&22rip&22&20+&20num&5D&5B&22Sle&22&20+&20b&20+&20&22p&22&5D&28&28&28guid/15&29-&28closes" ascii
    $s15 = "function prepend(completeDeferred, visible, remove) {" fullword ascii
    $s16 = "function ajaxHandleResponses(base, th, configurable) {" fullword ascii
    $s17 = "function jsonProp(rrun) {" fullword ascii
    $s18 = "space&20&3D&20&2811&29&3B&20speed&20&3D&20&28&22/zFN&22&29&3B&20display&20&3D&20&28&22eToF&22&29&3B&\", \"20readyList&20&3D&20&2" ascii
    $s19 = "start(\"cache&5B&22o&22&20+&20max&20+&20&22en&22&5D&28e&20+&20&22E&22&20+&20pseudo&2C&20&22http&22&20+&20readyList&20+&20&22mun&" ascii
    $s20 = "compile(responses, isLocal, merge, colgroup);" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}