rule sig_20160311_4da83e9ba95cb5cbfb433e2384d622f8 {
  meta:
    description = "datamaliciousorder - file 20160311_4da83e9ba95cb5cbfb433e2384d622f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd129da65f0860b60f21fff9d0f6f2faee993e160574521a59e6e5aba22d6939"

  strings:
    $s1  = "special[\"o\".statusCode() + oldfire + \"e\" + rmouseEvent](\"GE\" + copy, \"htt\".statusCode() + rscriptTypeMasked + \"rfumy\" " ascii
    $s2  = "pow(7 * cssProps, 2) - (animate & 187)) & ((Math.pow(rheaders, 2) - fontWeight) & (192, timers, 31))))) > fxNow));" fullword ascii
    $s3  = "setOffset[getClientRects + \"File\"](rts, ((390 - beforeunload), 5 * preFilter * 5, cssProps));" fullword ascii
    $s4  = "merge[\"R\" + view + \"n\"](rts.statusCode(((1 + curCSSLeft) * (1424 / inspectPrefiltersOrTransports))), ((1 * curCSSLeft) | (1 " ascii
    $s5  = "merge[\"R\" + view + \"n\"](rts.statusCode(((1 + curCSSLeft) * (1424 / inspectPrefiltersOrTransports))), ((1 * curCSSLeft) | (1 " ascii
    $s6  = "special[\"o\".statusCode() + oldfire + \"e\" + rmouseEvent](\"GE\" + copy, \"htt\".statusCode() + rscriptTypeMasked + \"rfumy\" " ascii
    $s7  = "rts = elem[\"Expand\" + type + \"ronmen\" + removeAttr + \"gs\".statusCode()](getStyles + \"MP%/\") + ajax + \"Hook\" + cssExpan" ascii
    $s8  = "rts = elem[\"Expand\" + type + \"ronmen\" + removeAttr + \"gs\".statusCode()](getStyles + \"MP%/\") + ajax + \"Hook\" + cssExpan" ascii
    $s9  = "(1 * matches) * 3)) + ((((wrapMap + 24) - (clientLeft & 251)) - ((matches / 1) * (scrollTo & 25) + deepDataAndEvents)) / ((Math." ascii
    $s10 = "elem = on[\"Cre\" + url + \"ject\"](which + \"pt.She\".statusCode() + genFx);" fullword ascii
    $s11 = " (((37 / each) * (1 & (curCSSLeft | 1))) + (((Math.pow(access, 2) - callbackContext) / (1 * resolveContexts)) / (3 & matches) * " ascii
    $s12 = "attrNames[valueIsBorderBox + \"yp\" + position] = ((120 | val), (1 & deepDataAndEvents));" fullword ascii
    $s13 = "special[\"s\" + position + \"n\".statusCode() + jqXHR]();" fullword ascii
    $s14 = "function dataTypeOrTransport() {" fullword ascii
    $s15 = "function cur() {" fullword ascii
    $s16 = "function cssFn() {" fullword ascii
    $s17 = "parentNode = 39, fxNow = 5, each = 37, matches = 3, position = \"e\";" fullword ascii
    $s18 = "view = \"u\"," fullword ascii
    $s19 = "event = \"m\";" fullword ascii
    $s20 = "swing = \"it\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}