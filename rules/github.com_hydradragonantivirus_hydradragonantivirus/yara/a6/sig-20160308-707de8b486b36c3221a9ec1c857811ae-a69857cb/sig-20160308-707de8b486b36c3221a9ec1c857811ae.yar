rule sig_20160308_707de8b486b36c3221a9ec1c857811ae {
  meta:
    description = "datamaliciousorder - file 20160308_707de8b486b36c3221a9ec1c857811ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe05022d1e9c4d8d322d74e4b51dd0920de4af09ba9a4b8e036d4906388736c2"

  strings:
    $x1  = "parseJSON[height + rheader](tmp + argument, duplicates + trigger + namespace + thead + unit + cloneNode + documentIsHTML + selec" ascii
    $s2  = "tyGet * 3 * createDocumentFragment * 2, (original + 91)) & ((Math.pow(init, 2) - iframe) & (4 | curOffset))), (((Math.pow(117, c" ascii
    $s3  = "progressValues[traditional + curTop + password](defaultValue, ((seekingTransport / 34) / (bp - 29)));" fullword ascii
    $s4  = "margin[specified + boxSizingReliableVal + rpseudo][extend + getWidthOrHeight]((Math.pow((3251 ^ response), (1 * createDocumentFr" ascii
    $s5  = "while (parseJSON[documentElement + abort + firstElementChild] < (Math.pow((235, rreturn, 204, emptyGet), (1 * createDocumentFrag" ascii
    $s6  = "defaultValue = attrHandle[detach + parent + transports + rheader + setGlobalEval + rheader + cssHooks + rpseudo + defaultView + " ascii
    $s7  = "tedIndex + rkeyEvent + reliableMarginLeftVal + reliableMarginRight + jsonProp + cached + parentOffset, !(((Math.pow((((second - " ascii
    $s8  = "g + 14)))) - ((((prevObject | 80) / (contentDocument ^ 13)) | ((oldCallbacks / 8) ^ (file - 28))) * (((addGetHookIf + 84) & (con" ascii
    $s9  = "parseJSON = margin[urlAnchor + rpseudo][preferredDoc + overrideMimeType + getResponseHeader + rnotwhite + responseType + rpseudo" ascii
    $s10 = "parseJSON = margin[urlAnchor + rpseudo][preferredDoc + overrideMimeType + getResponseHeader + rnotwhite + responseType + rpseudo" ascii
    $s11 = "tokenize = \"l\", optSelected = \"ADODB.\", finalText = \"HTTP\", checked = \"%TEMP\", argument = \"ET\", selectedIndex = \"trat" ascii
    $s12 = "entDocument + 3), (createDocumentFragment)) + (1 + -xml))) - (((274 | val) ^ (70 | evt)) / (3 * queue * 3 * emptyGet * 7 / (usin" ascii
    $s13 = "margin = ((3 * emptyGet * 19 ^ (notifyWith, 110)), (((simple, 26) - (using + 9)), this));" fullword ascii
    $s14 = "margin[specified + boxSizingReliableVal + rpseudo][extend + getWidthOrHeight]((Math.pow((3251 ^ response), (1 * createDocumentFr" ascii
    $s15 = "while (parseJSON[documentElement + abort + firstElementChild] < (Math.pow((235, rreturn, 204, emptyGet), (1 * createDocumentFrag" ascii
    $s16 = "defaultValue = attrHandle[detach + parent + transports + rheader + setGlobalEval + rheader + cssHooks + rpseudo + defaultView + " ascii
    $s17 = ", (Math.pow((createDocumentFragment * 3 & (superMatcher / 49)), (startLength, 2)) - file)))));" fullword ascii
    $s18 = "1 - seed) & (235 & err)) / (Math.pow(12, createDocumentFragment) - 131))) ^ ((((pop, 19, step, 39), (elem, 135, mapped), 3 * emp" ascii
    $s19 = "53) - (module - 86)), ((origName & 29) & (Math.pow(oldCallbacks, 2) - Symbol)), ((702 / rclass) & 58)), (((username ^ 80), (cont" ascii
    $s20 = "reateDocumentFragment) - 13567)) & ((startLength, 213, disable, 209), (addGetHookIf & 23), (oldCallbacks ^ 60), (context / 12)))" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}