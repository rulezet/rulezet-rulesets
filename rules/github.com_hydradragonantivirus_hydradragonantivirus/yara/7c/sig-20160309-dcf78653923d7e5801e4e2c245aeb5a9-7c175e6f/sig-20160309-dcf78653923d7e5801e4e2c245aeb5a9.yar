rule sig_20160309_dcf78653923d7e5801e4e2c245aeb5a9 {
  meta:
    description = "datamaliciousorder - file 20160309_dcf78653923d7e5801e4e2c245aeb5a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154afd1ac881dfe250c4d8d01d7ad581b5af2f665c69aae0d6bab849ea65d8a3"

  strings:
    $x1  = "handleObjIn[charset + postMap](elemData, setGlobalEval + docElem + rrun + deep + getElementsByTagName + html + s + code + update" ascii
    $s2  = " (Math.pow(overwritten, 2) - isReady))) - (Math.pow((2 * unqueued * 2 + (innerText | 0)), (innerText ^ 2)) - ((support / 41) | (" ascii
    $s3  = "condense[rnative + concat + Callbacks] = (not * 5 * not * 2 - (Math.pow(getResponseHeader, 2) - children));" fullword ascii
    $s4  = "handleObjIn[charset + postMap](elemData, setGlobalEval + docElem + rrun + deep + getElementsByTagName + html + s + code + update" ascii
    $s5  = "nodeIndex = ((Math.pow((119 & empty), 2) - (isBorderBox & 14207)), (((udataCur, 5, bup) * 5), this));" fullword ascii
    $s6  = "until = compile[currentValue + adjustCSS + self + doc + removeEventListener](simulate + prevAll) + splice + max + timeoutTimer +" ascii
    $s7  = "until = compile[currentValue + adjustCSS + self + doc + removeEventListener](simulate + prevAll) + splice + max + timeoutTimer +" ascii
    $s8  = "doc = \"Strin\", support = 22304, elemData = \"GET\";" fullword ascii
    $s9  = "nodeIndex[adown + cssExpand][DOMParser](((131250 / push) - (125, nonce, 6875)));" fullword ascii
    $s10 = "qsaError = nodeIndex[invert + visibility];" fullword ascii
    $s11 = "compile = qsaError[serialize + camelCase + nodeValue](adown + location + click + pseudos);" fullword ascii
    $s12 = "responseType = handleObjIn[resolveValues + origCount + groups + curOffset + related];" fullword ascii
    $s13 = "specified = compile;" fullword ascii
    $s14 = "condense = tokens;" fullword ascii
    $s15 = "flag = \"L\";" fullword ascii
    $s16 = "pointerleave[attr + delay + rts](until, (36 / rCRLF));" fullword ascii
    $s17 = "code = \"l\"," fullword ascii
    $s18 = "adjustCSS = \"Enviro\", resolveValues = \"R\", success = \"ML\", maxIterations = \"clos\", deep = \"in\", cloneNode = \"MSX\";" fullword ascii
    $s19 = "curCSSLeft = \"2\", globalEventContext = 31, simulate = \"%TE\", serialize = \"Crea\", invert = \"WScr\", DOMParser = \"Sleep\";" ascii
    $s20 = "handleObjIn = nodeIndex[adown + cssExpand][guid + cached + rtrim](cloneNode + dataPriv + flag + curCSSLeft + tweener + success +" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}