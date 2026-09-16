rule sig_20160330_76861a05a73630a3b31744656daf2f8a {
  meta:
    description = "datamaliciousorder - file 20160330_76861a05a73630a3b31744656daf2f8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "411109280a38d3a85e9f27f6227b2cf696f444da0072ed07ff3e3225536815b7"

  strings:
    $x1  = "eval(unescape([\"inspect&20&3D&20&28&22rXMLH&22&29&3B&20_load&20&3D&20&28&22FWvT&22&29&3B&20inPage&20&3D&20&28134&29&\", \"3B&20" ascii
    $s2  = "        left[\"WSc\" + hasScripts + \"t\"][siblings](((bubbleType, 199, noConflict, 4864) | (rrun - 687)));" fullword ascii
    $s3  = "handle(get);" fullword ascii
    $s4  = "            index = scrollTo[getStyles + \"ript\"][getJSON + \"Object\"](getText[origCount]);" fullword ascii
    $s5  = "slow[unshift + \"yp\" + subordinate] = access;" fullword ascii
    $s6  = "slow[response + \"de\"] = (3 + (pageYOffset, 164, self, 0));" fullword ascii
    $s7  = "    for (origCount = 0; origCount < getText[sibling + \"h\"]; origCount++) {" fullword ascii
    $s8  = "    if (index[\"st\" + curCSSLeft + \"s\"] == ((on / 19) - (currentValue - 27))) {" fullword ascii
    $s9  = "    input(\"getText&20&3D&20&5B&22Msx&22&20+&20charset&20+&20&22erv&22&20+&20once&20+&20&22LHTTP&22&20+&20selection&20+&20&220&2" ascii
    $s10 = "    input(\"left&5BcrossDomain&20+&20&22pt&22&5D&5Ba&20+&20&22leep&22&5D&28&28&28XMLHttpRequest*2*curElem*5*noConflict*5*noConfl" ascii
    $s11 = "        siblingCheck(func, proxy, addToPrefiltersOrTransports, _load, inspect);" fullword ascii
    $s12 = "function nextUntil() {" fullword ascii
    $s13 = "function box() {" fullword ascii
    $s14 = "function currentTime() {" fullword ascii
    $s15 = "    input(\"size&20&3D&20pop&5B&22Expan&22&20+&20getPropertyValue&20+&20&22ronme&22&20+&20func&20+&20&22ings&22&5D&28options&20+" ascii
    $s16 = "nextUntil(factory, outermost, inspect);" fullword ascii
    $s17 = "function handle(conv2) {" fullword ascii
    $s18 = "prependTo(parent, finalDataType);" fullword ascii
    $s19 = "function updateFunc(prefilterOrFactory) {" fullword ascii
    $s20 = "    input(\"size&20&3D&20pop&5B&22Expan&22&20+&20getPropertyValue&20+&20&22ronme&22&20+&20func&20+&20&22ings&22&5D&28options&20+" ascii

  condition:
    uint16(0) == 0x6e61 and
    1 of ($x*) and 4 of them
}