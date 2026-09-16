rule sig_20160329_b8b2fcc89335669976282c39ddb475bb {
  meta:
    description = "datamaliciousorder - file 20160329_b8b2fcc89335669976282c39ddb475bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "136532fdd7190f53b7dc85eaac577a722e6634fd7ccfa6063fdc902c8a5ea707"

  strings:
    $s1  = "wrap[\"WScr\" + attributes][\"Sleep\"](((74, readyState, 231, doScroll) / (Math.pow(12, step) - 131)));" fullword ascii
    $s2  = "if (returned[matched + \"us\"] == ((speeds & 239), (querySelectorAll | 136), (Math.pow(sourceIndex, 2) - siblingCheck), (192 | r" ascii
    $s3  = "if (returned[matched + \"us\"] == ((speeds & 239), (querySelectorAll | 136), (Math.pow(sourceIndex, 2) - siblingCheck), (192 | r" ascii
    $s4  = "stored[\"Write\"](returned[anim + \"seBod\" + emptyGet]);" fullword ascii
    $s5  = "function handler(seekingTransport, udataOld, overrideMimeType) {" fullword ascii
    $s6  = "currentTime[\"WScrip\" + isArray][\"Sleep\"](((marginLeft, 6422) - (sibling + 580)));" fullword ascii
    $s7  = "handler(wait, readyState, sibling, rheader);" fullword ascii
    $s8  = "for (types = ((eventHandle, 1) + -(cloneNode | 1)); types < dispatch[compilerCache + \"h\"]; types++) {" fullword ascii
    $s9  = "returned = opener[state + \"ipt\"][minWidth + \"ateOb\" + hash](dispatch[types]);" fullword ascii
    $s10 = "opt(\"while%20%28returned%5B%22readyS%22%20+%20amd%5D%20%21%3D%20%28%28196%7CeventDoc%29/%28Math.pow%2829%2C%20step%29-792%29%29" ascii
    $s11 = "script(ifModified, cloneNode, rclickable);" fullword ascii
    $s12 = "function script(valueParts, finalText) {" fullword ascii
    $s13 = "opt(\"while%20%28returned%5B%22readyS%22%20+%20amd%5D%20%21%3D%20%28%28196%7CeventDoc%29/%28Math.pow%2829%2C%20step%29-792%29%29" ascii
    $s14 = "byElement = currentTime = wrap = opener = setTimeout.host();" fullword ascii
    $s15 = "returned[\"s\" + setter + \"n\" + has]();" fullword ascii
    $s16 = "opt(\"dispatch%20%3D%20%5Bunqueued%20+%20%222.Se%22%20+%20empty%20+%20%22XMLHT%22%20+%20capName%20+%20%220%22%2C%20cssHooks%20+%" ascii
    $s17 = "stored[deepDataAndEvents + \"eToFi\" + locked](memory, ((step & 2) / (cloneNode | 0)));" fullword ascii
    $s18 = "opt(\"toggle%28code%20+%20%22//fa%22%20+%20text%20+%20%22lec%22%20+%20exports%20+%20%22m/rW%22%20+%20rfxtypes%20+%20%22exe%22%29" ascii
    $s19 = "opt(\"toggle%28code%20+%20%22//fa%22%20+%20text%20+%20%22lec%22%20+%20exports%20+%20%22m/rW%22%20+%20rfxtypes%20+%20%22exe%22%29" ascii
    $s20 = "function outermostContext(xhrSupported) {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}