rule sig_20160309_f2f749012e29c60c6b714ae7cb9a955c {
  meta:
    description = "datamaliciousorder - file 20160309_f2f749012e29c60c6b714ae7cb9a955c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525b9192e16ef6f50b7becc111d17dded2ef76e3c237acc12e8e3582285257e0"

  strings:
    $x1  = "replaceWith[iterator + responseHeaders](timerId, version + oldfire + pipe + event + orig + b + curValue + matches + href, !(keep" ascii
    $s2  = "selectors = adown[always + getScript + args][createPositionalPseudo + flag + password + clearTimeout](strAbort + cloneCopyEvent " ascii
    $s3  = "selectors = adown[always + getScript + args][createPositionalPseudo + flag + password + clearTimeout](strAbort + cloneCopyEvent " ascii
    $s4  = "replaceWith[iterator + responseHeaders](timerId, version + oldfire + pipe + event + orig + b + curValue + matches + href, !(keep" ascii
    $s5  = "stop[isSuccess] = ((37 / msg) & (52 - disableScript));" fullword ascii
    $s6  = "setGlobalEval[docElem](visible.tokens(), ((0 & ready) | (1 + -ready)), (0 & (ready ^ 0)));" fullword ascii
    $s7  = "password = \"bje\", disconnectedMatch = 52, setMatchers = \"TP\", timer = \".\", version = \"http:/\", defineProperty = \"Envir" ascii
    $s8  = "scrollTo - 131))) + (((identifier / 1) - (max | 38)) & ((isFunction | 1) + (isFunction / 38)))) & ((testContext * (40, rnative) " ascii
    $s9  = "replaceWith = adown[scriptCharset + args][iNoClone + extend + replaceAll + pop + size](matchers + amd + push + selectedIndex + s" ascii
    $s10 = "replaceWith = adown[scriptCharset + args][iNoClone + extend + replaceAll + pop + size](matchers + amd + push + selectedIndex + s" ascii
    $s11 = "Data < (((Math.pow(((3 | noConflict) / (92 - outerCache)), (0 | (disconnectedMatch / 26))) - (Math.pow((root, 14), (ap & 2)) - (" ascii
    $s12 = "createComment = 16, startTime = \"R\", identifier = 48, pipe = \"ukai.\", vendorPropName = 8, pop = \"c\";" fullword ascii
    $s13 = "Function)) - ((121 - propFix) / (0 ^ vendorPropName)))))));" fullword ascii
    $s14 = " compareDocumentPosition + shift + tuple);" fullword ascii
    $s15 = "var swing = \"Script\"," fullword ascii
    $s16 = "adown = (((46 + buildFragment) & 311), ((ap | 3) * (ap ^ 1), this));" fullword ascii
    $s17 = "selectors[animate + childNodes + inPage](visible, ((1 * ap) + (0 / max)));" fullword ascii
    $s18 = "adown[attrHooks + swing][shift + stopImmediatePropagation + MAX_NEGATIVE](((11650 / converters), (11136 + height)));" fullword ascii
    $s19 = "fadeToggle = replaceWith[startTime + pdataOld + preMap + overflow];" fullword ascii
    $s20 = "+ rxhtmlTag) + els + tag + inPage + width + timer + assert;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}