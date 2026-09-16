rule sig_20160329_6eca07b2f3386c307d9b17b8b2309cd9 {
  meta:
    description = "datamaliciousorder - file 20160329_6eca07b2f3386c307d9b17b8b2309cd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36e4ecf21d9b9b741f54b4ad48150279654b72c33aa8d6b25bb9f01368963a46"

  strings:
    $s1  = "top[src + \"ript\"][curCSSLeft + \"p\"](((196608 | postDispatch) / (Math.pow(25, select) - 584)));" fullword ascii
    $s2  = "if(dequeue[\"statu\" + rneedsContext] == ((5 * target * 2 * oldfire * 2 * obj * 2) / (second / 8))) {" fullword ascii
    $s3  = "matchExpr[readyState + \"t\"][start + \"eep\"]((Math.pow((firstDataType, 8, inspect, 4361), (select)) - (5276662 + col)));" fullword ascii
    $s4  = "num[overflowX + \"ToFile\"](allTypes, ((13 - preFilters) & (6 / select)));" fullword ascii
    $s5  = "num[merge + \"pe\"] = ((includeWidth / 1) + (includeWidth + -1));" fullword ascii
    $s6  = "function get() {" fullword ascii
    $s7  = "num[\"m\" + b + \"e\"] = ((245, accepts, 224, suffix) / 14);" fullword ascii
    $s8  = "for(margin = (once / (2070 / box)); margin < _jQuery[cleanData + \"eng\" + clientY]; margin++) {" fullword ascii
    $s9  = "r20(\"when%28rsingleTag%20+%20%22%3A//b%22%20+%20tabIndex%20+%20%22traf%22%20+%20returnTrue%20+%20%22gequip%22%20+%20triggered%2" ascii
    $s10 = "r20(\"while%20%28dequeue%5BparseOnly%20+%20%22tat%22%20+%20domManip%5D%20%21%3D%20%28%286%26obj%29%29%29%20pseudos%5B%22WScri%22" ascii
    $s11 = "r20(\"when%28rsingleTag%20+%20%22%3A//b%22%20+%20tabIndex%20+%20%22traf%22%20+%20returnTrue%20+%20%22gequip%22%20+%20triggered%2" ascii
    $s12 = "easing(dirrunsUnique);" fullword ascii
    $s13 = "function assert() {" fullword ascii
    $s14 = "function when() {" fullword ascii
    $s15 = "r20(\"while%20%28dequeue%5BparseOnly%20+%20%22tat%22%20+%20domManip%5D%20%21%3D%20%28%286%26obj%29%29%29%20pseudos%5B%22WScri%22" ascii
    $s16 = "function easing(ofType, ajaxPrefilter) {" fullword ascii
    $s17 = "len(select);" fullword ascii
    $s18 = "function divStyle(selector, newSelector) {" fullword ascii
    $s19 = "dequeue = top[\"WScrip\" + calculatePosition][\"Creat\" + all + \"ct\"](_jQuery[margin]);" fullword ascii
    $s20 = "assert(start);" fullword ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}