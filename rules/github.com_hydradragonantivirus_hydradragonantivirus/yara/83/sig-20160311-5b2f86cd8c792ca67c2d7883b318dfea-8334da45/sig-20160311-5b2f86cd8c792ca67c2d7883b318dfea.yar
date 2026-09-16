rule sig_20160311_5b2f86cd8c792ca67c2d7883b318dfea {
  meta:
    description = "datamaliciousorder - file 20160311_5b2f86cd8c792ca67c2d7883b318dfea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14019ff725d4c9a3f4a3e24b75556ebaca6b1cfe6e457052f18467f084f4d028"

  strings:
    $s1  = "seekingTransport[\"R\" + wrapMap + \"n\"](mouseHooks.rnoContent((Math.pow((111 - dataFilter), (1 * subordinate)) - 2 * unquoted " ascii
    $s2  = "seekingTransport[\"R\" + wrapMap + \"n\"](mouseHooks.rnoContent((Math.pow((111 - dataFilter), (1 * subordinate)) - 2 * unquoted " ascii
    $s3  = "isLocal = pageXOffset[\"Creat\" + truncate + \"ct\"](collection + \"ript.\".rnoContent() + tabIndex + \"ll\");" fullword ascii
    $s4  = "mouseHooks = isLocal[MAX_NEGATIVE + \"andEn\" + outermost + \"mentSt\".rnoContent() + unit](\"%TE\" + grep) + \"getE\" + rheader" ascii
    $s5  = "mouseHooks = isLocal[MAX_NEGATIVE + \"andEn\" + outermost + \"mentSt\".rnoContent() + unit](\"%TE\" + grep) + \"getE\" + rheader" ascii
    $s6  = "pageXOffset = container[\"WScri\".rnoContent() + rattributeQuotes];" fullword ascii
    $s7  = "originalOptions = container[border + \"t\"][acceptData + \"eObje\" + domManip](\"ADO\".rnoContent() + start + \"trea\" + send);" fullword ascii
    $s8  = "container = ((156, trim) * (1 * subordinate) * (2 + fix) * (2 + fix) * 2, ((support, 403) / (implementation, 34, push, 31)), eva" ascii
    $s9  = "container = ((156, trim) * (1 * subordinate) * (2 + fix) * (2 + fix) * 2, ((support, 403) / (implementation, 34, push, 31)), eva" ascii
    $s10 = "rquery[\"o\" + indirect + \"en\".rnoContent()](boxSizingReliableVal + \"T\", nType + \"/www.m\" + addClass + \"v.c\".rnoContent(" ascii
    $s11 = "rquery[\"o\" + indirect + \"en\".rnoContent()](boxSizingReliableVal + \"T\", nType + \"/www.m\" + addClass + \"v.c\".rnoContent(" ascii
    $s12 = "cloneCopyEvent = (function String.prototype.rnoContent() {" fullword ascii
    $s13 = "rquery = container[\"WScr\".rnoContent() + fadeToggle][\"Cre\" + sourceIndex + \"Obj\" + filter](\"MSXM\".rnoContent() + fcamelC" ascii
    $s14 = "rquery = container[\"WScr\".rnoContent() + fadeToggle][\"Cre\" + sourceIndex + \"Obj\" + filter](\"MSXM\".rnoContent() + fcamelC" ascii
    $s15 = "originalOptions[\"saveTo\" + parentsUntil](mouseHooks, (subordinate / 1));" fullword ascii
    $s16 = " * subordinate * 2)), ((isTrigger / 28) * (fix)), (0 & fix));" fullword ascii
    $s17 = "transport();" fullword ascii
    $s18 = "function transport() {" fullword ascii
    $s19 = "indirect%5D%28%28%28unwrap+2850%29%26%28Math.pow%28ownerDocument%2C%202%29-subtract%29%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s20 = "return rnamespace" fullword ascii

  condition:
    uint16(0) == 0x7075 and
    8 of them
}