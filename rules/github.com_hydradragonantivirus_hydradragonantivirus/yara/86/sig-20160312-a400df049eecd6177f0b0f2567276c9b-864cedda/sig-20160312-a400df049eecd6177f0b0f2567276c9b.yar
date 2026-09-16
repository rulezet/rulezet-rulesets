rule sig_20160312_a400df049eecd6177f0b0f2567276c9b {
  meta:
    description = "datamaliciousorder - file 20160312_a400df049eecd6177f0b0f2567276c9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27585ee368798ecbe9ecd4730bff87de96d43ac0d9dabbb92f7b0056a5381604"

  strings:
    $s1  = "propHooks[rdashAlpha + \"pe\".matched() + PI](\"GE\" + parentNode, \"http:/\" + indirect + \"bilit\".matched() + prevObject + \"" ascii
    $s2  = " setter, !(rhash < ((((1 * throws) - (70 - keepScripts)) & 2) & (((tbody - 43) | (nodeValue * 1)) | ((random * 2 + matchIndexes)" ascii
    $s3  = "rnotwhite = \"ToFi\", getter = \"Crea\", isNumeric = \"r\", scripts = 39, list = \"t\";" fullword ascii
    $s4  = "qualifier = ((151 * jQuery - (25 & hash)), ((7 * parsed + 2) & (nodeValue * 19)), eval(\"th\" + parseFromString));" fullword ascii
    $s5  = " - 47))) * ((hash / 27) * (jQuery & 3)) * (((nodeValue + (1 + -nodeValue)) * ((5 & div1) - (3 & parsed))) & (((252 & removeAttr)" ascii
    $s6  = "current[\"save\".matched() + rnotwhite + \"le\"](border, (78 / scripts));" fullword ascii
    $s7  = "current = qualifier[rnumnonpx + \"pt\"][getter + \"teObj\" + reliableMarginLeft](\"ADO\".matched() + superMatcher + \"trea\" + c" ascii
    $s8  = "\".matched() + contents;" fullword ascii
    $s9  = "border = timerId[slideToggle + \"Enviro\" + parentOffset + \"ntStri\".matched() + settings](\"%TE\" + attrId) + \"cu\" + isNumer" ascii
    $s10 = "propHooks = qualifier[\"WScr\" + sibling][\"Creat\" + msMatchesSelector + \"ct\".matched()](v + \"L2.XML\" + rnoInnerhtml + \"P" ascii
    $s11 = "propHooks[rdashAlpha + \"pe\".matched() + PI](\"GE\" + parentNode, \"http:/\" + indirect + \"bilit\".matched() + prevObject + \"" ascii
    $s12 = "contents = \"cr\";" fullword ascii
    $s13 = "animated = qualifier[\"WScri\".matched() + appendChild];" fullword ascii
    $s14 = "border = timerId[slideToggle + \"Enviro\" + parentOffset + \"ntStri\".matched() + settings](\"%TE\" + attrId) + \"cu\" + isNumer" ascii
    $s15 = "var hash = 27," fullword ascii
    $s16 = "  return merge" fullword ascii
    $s17 = "function m() {" fullword ascii
    $s18 = "function src() {" fullword ascii
    $s19 = "function marginLeft() {" fullword ascii
    $s20 = "function w() {" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}