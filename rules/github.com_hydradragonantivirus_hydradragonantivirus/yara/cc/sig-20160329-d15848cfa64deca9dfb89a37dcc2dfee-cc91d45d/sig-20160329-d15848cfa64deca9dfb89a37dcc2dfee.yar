rule sig_20160329_d15848cfa64deca9dfb89a37dcc2dfee {
  meta:
    description = "datamaliciousorder - file 20160329_d15848cfa64deca9dfb89a37dcc2dfee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af1d7c45d3b741e8917633ac30e87fa5d467cb78198f042998cc7e522500ecaa"

  strings:
    $s1  = "completed(\"while%20%28overflowY%5B%22ready%22%20+%20manipulationTarget%20+%20%22te%22%5D%20%21%3D%20%28%28colgroup%263%29*%28co" ascii
    $s2  = "completed(\"while%20%28overflowY%5B%22ready%22%20+%20manipulationTarget%20+%20%22te%22%5D%20%21%3D%20%28%28colgroup%263%29*%28co" ascii
    $s3  = "for (valueIsBorderBox = ((238, bup) * (1 + -bup)); valueIsBorderBox < orig[token + \"ength\"]; valueIsBorderBox++) {" fullword ascii
    $s4  = "if (overflowY[\"status\"] == ((13 + eq), (7 * adown + 6), (fix - 75))) {" fullword ascii
    $s5  = "swing = cssFn = noop = suffix = hasOwn.temp();" fullword ascii
    $s6  = "swing[reliableMarginRight + \"ipt\"][l]((Math.pow((208600 / useCache), (32 / bulk)) - (Math.pow(10836499, colgroup) - 1174296931" ascii
    $s7  = "swing[reliableMarginRight + \"ipt\"][l]((Math.pow((208600 / useCache), (32 / bulk)) - (Math.pow(10836499, colgroup) - 1174296931" ascii
    $s8  = "group%7C2%29%29%29%20cssFn%5BactiveElement%20+%20%22rip%22%20+%20unbind%5D%5B%22Sl%22%20+%20qsaError%5D%28%28%28bup+1%29*%28firi" ascii
    $s9  = "argument(getStyles, sort, adown, write);" fullword ascii
    $s10 = "function rheader(PI, _removeData) {" fullword ascii
    $s11 = "rheader(bup, getResponseHeader, matchedCount, sibling);" fullword ascii
    $s12 = "overflowY = swing[activeElement + \"ript\"][matchedCount + \"eObje\" + elemdisplay](orig[valueIsBorderBox]);" fullword ascii
    $s13 = "rneedsContext[\"Ru\" + find](cssNormalTransform);" fullword ascii
    $s14 = "chainable(fxNow, unbind, clearTimeout, setTimeout, stop);" fullword ascii
    $s15 = "fragment(clearTimeout, func, qsaError, DOMParser);" fullword ascii
    $s16 = "function completed(fadeOut) {" fullword ascii
    $s17 = "createFxNow(fontWeight, token);" fullword ascii
    $s18 = "function adjustCSS(removeEventListener) {" fullword ascii
    $s19 = "} catch (content) {" fullword ascii
    $s20 = "function risSimple() {" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}