rule sig_20160309_926f722a685303533b455802a349b107 {
  meta:
    description = "datamaliciousorder - file 20160309_926f722a685303533b455802a349b107.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d227995990aed2710059649eb1313172a2f6d292f3e7f8ee4f29cd23acc2a6b"

  strings:
    $s1  = "startLength[unbind + rescape](always + pnum, ifModified + defaultView + isArray + anim + bool + offsetWidth + fixInput + parent " ascii
    $s2  = "guid[value](_removeData.iterator(), ((Math.pow(argument, 2) - w), (87, identifier, 0)), (srcElements & (0 ^ rsibling)));" fullword ascii
    $s3  = "selector = j[last + scrollTo + selection][cssProps + speed + replaceAll](valueParts + textContent + createTextNode + iframe);" fullword ascii
    $s4  = "j[className + sel + async][forward + style](((nativeStatusText - 9186)));" fullword ascii
    $s5  = "_removeData = mouseHooks[compareDocumentPosition + jQuery + uid + focus + file + push + startTime](sortInput + originalOptions) " ascii
    $s6  = "_removeData = mouseHooks[compareDocumentPosition + jQuery + uid + focus + file + push + startTime](sortInput + originalOptions) " ascii
    $s7  = "scrollTo = \"cr\", constructor = \"Run\", bool = \"tem\", qsaError = \"8n\", cssFn = \"WScr\";" fullword ascii
    $s8  = "responseHeadersString = selector;" fullword ascii
    $s9  = "forward = \"S\";" fullword ascii
    $s10 = "j = (((10658 + close) / (550 / define)), ((1 * (defaultExtra + 0)), this));" fullword ascii
    $s11 = "styles = startLength[shift + pseudo + iNoClone];" fullword ascii
    $s12 = "marginLeft[nextUntil + clone]();" fullword ascii
    $s13 = "selector[detach + unloadHandler + boxSizingReliableVal](_removeData, ((siblings & 30) / (ajaxPrefilter & 15)));" fullword ascii
    $s14 = "overflowY = \"type\", defaultView = \"p://s\", unbind = \"o\";" fullword ascii
    $s15 = "udataCur = \"write\", identifier = 48, preventDefault = 3, parentWindow = \".sc\";" fullword ascii
    $s16 = "startLength[unbind + rescape](always + pnum, ifModified + defaultView + isArray + anim + bool + offsetWidth + fixInput + parent " ascii
    $s17 = "iframe = \"tream\", speed = \"Obj\";" fullword ascii
    $s18 = "cssProps = (function String.prototype.iterator() {" fullword ascii
    $s19 = "file = \"nt\", matchesSelector = 38;" fullword ascii
    $s20 = "var detach = \"saveT\"," fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}