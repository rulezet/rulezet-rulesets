rule sig_20160330_9231f5dd7e927e7af4bf20df5dc3d791 {
  meta:
    description = "datamaliciousorder - file 20160330_9231f5dd7e927e7af4bf20df5dc3d791.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b09ca55d04a258b9bf5351c7f793b6948831b23231ecec25779cb49bca3706b"

  strings:
    $x1  = "eval(unescape([\"var&20isFunction&20&3D&20&28&22pe&22&29&2C&20noop&20&3D&20&28214&29&2C&20getAll&20&3D&20&28&22resp&2\", \"2&29&" ascii
    $s2  = "  pipe[crossDomain + \"eToFi\" + password](curCSSLeft, ((rchecked - 34)));" fullword ascii
    $s3  = "function overwritten(delegateTarget, processData, handle) {" fullword ascii
    $s4  = " inspect(\"getScript&28&22htt&22&20+&20attrHooks&20+&20&22anmch&22&20+&20returned&20+&20&22om/y&22&20+&20collection&20+&20&228.e" ascii
    $s5  = " inspect(\"curCSSLeft&20&3D&20run&5B&22Expa&22&20+&20unique&20+&20&22iro&22&20+&20tmp&20+&20&22ntSt&22&20+&20rnotwhite&5D&28&22&" ascii
    $s6  = "  pipe[serialize + \"te\"](pseudo[getAll + \"onseBo\" + select]);" fullword ascii
    $s7  = " if(pseudo[fail + \"atu\" + dest] == ((Math.pow(71, dir) - 4966) * (dir) + (100 / dir))) {" fullword ascii
    $s8  = "function getScript() {" fullword ascii
    $s9  = " inspect(\"getScript&28&22htt&22&20+&20attrHooks&20+&20&22anmch&22&20+&20returned&20+&20&22om/y&22&20+&20collection&20+&20&228.e" ascii
    $s10 = "  pipe[\"op\" + check + \"n\"]();" fullword ascii
    $s11 = "pipe[\"ty\" + isFunction] = ((1 + nodeType) | 0);" fullword ascii
    $s12 = "function special(currentTarget, genFx) {" fullword ascii
    $s13 = " inspect(\"pipe&20&3D&20m&5BmozMatchesSelector&20+&20&22ipt&22&5D&5BdefaultPrevented&20+&20&22teObje&22&20+&20dataTypes&5D&28&22" ascii
    $s14 = " for(getStyles = ((focusin, 0, noop, 0) / (prepend * 5)); getStyles < accepts[all + \"h\"]; getStyles++) {" fullword ascii
    $s15 = " inspect(\"curCSSLeft&20&3D&20run&5B&22Expa&22&20+&20unique&20+&20&22iro&22&20+&20tmp&20+&20&22ntSt&22&20+&20rnotwhite&5D&28&22&" ascii
    $s16 = " inspect(\"pipe&5Belements&20+&20&22od&22&20+&20check&5D&20&3D&20&28&281*prepend&29*&281*old&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s17 = " inspect(\"pipe&20&3D&20m&5BmozMatchesSelector&20+&20&22ipt&22&5D&5BdefaultPrevented&20+&20&22teObje&22&20+&20dataTypes&5D&28&22" ascii
    $s18 = "jsonp(getter, n);" fullword ascii
    $s19 = "function elemdisplay(add, eased, content) {" fullword ascii
    $s20 = "   pseudo = doneName[num + \"pt\"][cssExpand + \"Objec\" + dataAttr](accepts[getStyles]);" fullword ascii

  condition:
    uint16(0) == 0x6669 and
    1 of ($x*) and 4 of them
}