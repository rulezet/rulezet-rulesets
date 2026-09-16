rule sig_20160308_f36cc17a161313234d6ac5af609c7b1b {
  meta:
    description = "datamaliciousorder - file 20160308_f36cc17a161313234d6ac5af609c7b1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efe749d20fa5abf047cbac1995567291aa207110539eb18097345fba60f43b00"

  strings:
    $x1  = "hash[compiled + push_native](now, unmatched + keyCode + toggle + curPosition + parentWindow + cssFn + rts + restoreScript, !((((" ascii
    $s2  = "newContext = (((Math.pow(190, parentNode) - 35887) ^ (XMLHttpRequest * 2 + animated)), (((1464 / result), (141 | getElementsByTa" ascii
    $s3  = "hash[compiled + push_native](now, unmatched + keyCode + toggle + curPosition + parentWindow + cssFn + rts + restoreScript, !((((" ascii
    $s4  = "newContext = (((Math.pow(190, parentNode) - 35887) ^ (XMLHttpRequest * 2 + animated)), (((1464 / result), (141 | getElementsByTa" ascii
    $s5  = "hash = newContext[selection + rnoContent + pageX + keys][onlyHandlers + classCache + prevObject + cssShow](display + pos + respo" ascii
    $s6  = "wrapInner[r20](getWindow.getClientRects(), 0, ((optall - 20) / (result * 3 + XMLHttpRequest)));" fullword ascii
    $s7  = "+ (28 | fix)) - ((1 * converters) ^ (Math.pow(38, parentNode) - 1403))), ((Math.pow((subtract - 36), (funcName * 2)) - (iframe -" ascii
    $s8  = "3 & (animated & 3))) & ((XMLHttpRequest | 3) - (Math.pow(animated, 2) - converters))) * ((((4 | parentNode) * (24 - DOMParser) +" ascii
    $s9  = " 2) / ((XMLHttpRequest | 4) | (updateFunc & 18))) * (((code / 16) | (Math.pow(mimeType, 2) - styles)) - (2 * parentNode * 2 * pa" ascii
    $s10 = "rentNode ^ (6 & oldfire)))) == ((((2186 + dataAttr) - (1544 + marginDiv)) / ((6 + exports) + (11 + Data))), ((((287 - cssProps) " ascii
    $s11 = " 38)) & ((exports + 43) - (newSelector ^ 24))), ((funcName | 4) ^ ((updateFunc - 4) | (hover)))))));" fullword ascii
    $s12 = "keyCode = \"p\", button = \"Run\", conv2 = \"Sleep\", toggle = \"://ozo\", mimeType = 23, requestHeaders = \"wo\";" fullword ascii
    $s13 = "hash = newContext[selection + rnoContent + pageX + keys][onlyHandlers + classCache + prevObject + cssShow](display + pos + respo" ascii
    $s14 = "getWindow = curCSS[dataFilter + rheaders + accepts + createOptions + get + concat](timers + rsingleTag) + test + requestHeaders " ascii
    $s15 = "setDocument[origName + parts + current](getWindow, ((0 | nonce) / 3 * parentNode * 2 * animated));" fullword ascii
    $s16 = "+ rdisplayswap + margin + rnoContent;" fullword ascii
    $s17 = "curCSS = setAttribute[rreturn + replaceAll + ignored + cssShow](selection + rnoContent + pageX + keys + constructor + caption);" fullword ascii
    $s18 = "context[implicitRelative + ignored] = ((attributes - 31) * (funcName + 0));" fullword ascii
    $s19 = "while (hash[clearCloneStyle + origCount + winnow] < 2 * (parentNode, 214, parentNode)) {" fullword ascii
    $s20 = "setDocument[preDispatch + ignored](hash[find + strAbort + rdashAlpha + iterator]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}