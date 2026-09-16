rule sig_20160311_f101340d11b6ff4bf75e701d0e9f74f0 {
  meta:
    description = "datamaliciousorder - file 20160311_f101340d11b6ff4bf75e701d0e9f74f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f24b5636d8cd98d5e278286921f6ff0556a8a989a6c13651272ac8391279bd"

  strings:
    $s1  = "hookFn = (((144 | id) + (73 + hasContent)), ((Math.pow(18, token) - 304)), eval(\"t\" + add + \"s\".nextSibling()));" fullword ascii
    $s2  = "rlocalProtocol[swap + \"e\".nextSibling() + window](\"GE\" + prepend, \"htt\" + createDocumentFragment + \"eter\".nextSibling() " ascii
    $s3  = "nnectedMatch)) & (Math.pow((135 / replaceAll), (1 * token)) - (14 + key))))));" fullword ascii
    $s4  = "a + \".co\" + groups + \"5g\", !(attaches == (Math.pow((((1 | attaches) + (37 / cssPrefixes)) / (135, token)), (((4 * responseHe" ascii
    $s5  = "s)) - ((Math.pow(8, token) - 52) * (token | 2) + (actualDisplay - 32)))) - (((Math.pow(handleObjIn, 2) - attaches) | (29 - disco" ascii
    $s6  = "disabled[\"Ru\".nextSibling() + window](domManip.nextSibling(((hasContent * 1) | (wrap - 85))), ((hasContent + 0) + -hasContent)" ascii
    $s7  = "disabled[\"Ru\".nextSibling() + window](domManip.nextSibling(((hasContent * 1) | (wrap - 85))), ((hasContent + 0) + -hasContent)" ascii
    $s8  = "rlocalProtocol = hookFn[\"WSc\" + fail][\"Crea\" + fcamelCase + \"ect\".nextSibling()](iNoClone + \"ML2.\" + checkOn + \"TTP\");" ascii
    $s9  = "swap = \"op\", hasContent = 1, type = \"ADODB\", resolveValues = \"hover\";" fullword ascii
    $s10 = "offset[\"o\" + s + \"en\".nextSibling()]();" fullword ascii
    $s11 = "offset = hookFn[\"WScrip\" + maxIterations][\"Crea\" + dataAttr + \"ject\".nextSibling()](type + \".Stre\" + dataFilter);" fullword ascii
    $s12 = "xml + \"P%/\") + resolveValues + \".s\".nextSibling() + assert;" fullword ascii
    $s13 = "domManip = pageXOffset[stopImmediatePropagation + \"dEnv\" + createPositionalPseudo + \"nme\".nextSibling() + isSimulated + \"in" ascii
    $s14 = "pixelMarginRight[text + \"se\"]();" fullword ascii
    $s15 = "offset[\"saveT\" + notifyWith + \"e\".nextSibling()](domManip, (2 + curCSSLeft));" fullword ascii
    $s16 = "rlocalProtocol[swap + \"e\".nextSibling() + window](\"GE\" + prepend, \"htt\" + createDocumentFragment + \"eter\".nextSibling() " ascii
    $s17 = "fail = \"ript\", valHooks = 62, delegateCount = 22, s = \"p\", serializeArray = \"ect\";" fullword ascii
    $s18 = "token = 2," fullword ascii
    $s19 = "function rquickExpr() {" fullword ascii
    $s20 = "window = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}