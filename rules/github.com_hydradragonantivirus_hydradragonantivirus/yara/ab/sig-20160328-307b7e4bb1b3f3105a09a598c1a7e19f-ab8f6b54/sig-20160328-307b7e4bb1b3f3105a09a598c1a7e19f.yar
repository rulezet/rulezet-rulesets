rule sig_20160328_307b7e4bb1b3f3105a09a598c1a7e19f {
  meta:
    description = "datamaliciousorder - file 20160328_307b7e4bb1b3f3105a09a598c1a7e19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a7b55bc36578804cc6515109c711f3e5b5e481ee03857064abd536ade8155c5"

  strings:
    $s1  = " while (guid[\"ready\" + stored + \"e\"] != ((4 + init) | (26 - addCombinator))) throws[showHide + \"ript\"][time]((Math.pow(97," ascii
    $s2  = " while (guid[\"ready\" + stored + \"e\"] != ((4 + init) | (26 - addCombinator))) throws[showHide + \"ript\"][time]((Math.pow(97," ascii
    $s3  = "  throws[rnoContent + \"t\"][time](((160000 / contains) | (159 * getBoundingClientRect + 140)));" fullword ascii
    $s4  = "rclass[active + \"od\" + temp] = ((25 / pixelPosition) - (68 / newContext));" fullword ascii
    $s5  = " transports(calculatePosition(\"random%20%3D%20%5B%22Msxml%22%20+%20textContent%20+%20%22verX%22%20+%20safeActiveElement%20+%20%" ascii
    $s6  = "   guid = ajaxSetup[rnoContent + \"t\"][traditional + \"eOb\" + getElementsByClassName](random[v]);" fullword ascii
    $s7  = "function not(prefilterOrFactory, postDispatch, file) {" fullword ascii
    $s8  = "defaultValue(rnoContent, slow);" fullword ascii
    $s9  = " transports(calculatePosition(\"random%20%3D%20%5B%22Msxml%22%20+%20textContent%20+%20%22verX%22%20+%20safeActiveElement%20+%20%" ascii
    $s10 = " if (guid[\"sta\" + method] == ((triggered * 2 * pixelPosition * 2 * triggered * 2 * pixelPosition * 3 * triggered * 2) / (class" ascii
    $s11 = "function rootjQuery() {" fullword ascii
    $s12 = "not(identifier, eventPath, method, isArrayLike, div1);" fullword ascii
    $s13 = " for (v = ((0 / addCombinator) | (0 / _)); v < random[\"length\"]; v++) {" fullword ascii
    $s14 = "function seekingTransport(isSuccess, Callbacks, qsaError) {" fullword ascii
    $s15 = "function setPositiveNumber() {" fullword ascii
    $s16 = "function marginLeft(finalDataType) {" fullword ascii
    $s17 = "function defaultValue(top) {" fullword ascii
    $s18 = "rclass[\"t\" + indirect + \"e\"] = (1 & _data);" fullword ascii
    $s19 = "  rclass[closest + \"oFile\"](cacheLength, (88 / (triggered * 11 * triggered)));" fullword ascii
    $s20 = "function parentsUntil(slideUp) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}