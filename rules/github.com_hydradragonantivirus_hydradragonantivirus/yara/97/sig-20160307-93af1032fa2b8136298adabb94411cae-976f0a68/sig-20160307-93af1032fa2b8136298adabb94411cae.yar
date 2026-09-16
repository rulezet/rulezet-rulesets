rule sig_20160307_93af1032fa2b8136298adabb94411cae {
  meta:
    description = "datamaliciousorder - file 20160307_93af1032fa2b8136298adabb94411cae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10658174de2258ac991452380f729a43962127f33e658e83c051304a2186dda5"

  strings:
    $s1  = "resolve[col + tick + focus](dispatch + dequeue, nType + anim + rparentsprev + protocol + getElementsByTagName + pattern + curEle" ascii
    $s2  = "m + pixelPositionVal + getAllResponseHeaders, !(10 < ((((reject / 14) / (inspectPrefiltersOrTransports * 1)) - ((split / 46) | (" ascii
    $s3  = "attachEvent & 31))) ^ ((inspectPrefiltersOrTransports ^ (45 - show)) & ((27 & load) - (12 * fixHooks + 1)))) * ((Math.pow((relia" ascii
    $s4  = "parse = \"clo\", wrapMap = \"s\", password = 680, rheaders = \"nd\";" fullword ascii
    $s5  = "pixelMarginRight[andSelf + len + eq][seed + rbrace](((Math.pow(11459, fixHooks) - 131288948) - (apply & 6911)));" fullword ascii
    $s6  = "    pixelMarginRight[defaultView + root + tag][seed + toggle + pdataCur](((328 | password) / (10 & bp)));" fullword ascii
    $s7  = "ransports) ^ 2 * rfocusMorph), (((3 & response) & (1 | response)) ^ (Math.pow((4 + inspectPrefiltersOrTransports), (126, handle," ascii
    $s8  = "resolve[col + tick + focus](dispatch + dequeue, nType + anim + rparentsprev + protocol + getElementsByTagName + pattern + curEle" ascii
    $s9  = "resolve[emptyGet + rheaders]();" fullword ascii
    $s10 = " 250, fixHooks)) - (0 | argument))))));" fullword ascii
    $s11 = "bleMarginLeft, 111, setOffset), 2) - (id | 2998)), ((delegateType / 43) & (indirect, 5)) * ((fixHooks * 3 + inspectPrefiltersOrT" ascii
    $s12 = "pixelMarginRight = ((1 | (Math.pow(sortInput, 2) - calculatePosition)), (((8 ^ split) * 2 + (replaceAll, 140, fixHooks)), this))" ascii
    $s13 = "resolve = pixelMarginRight[marginLeft + overwritten][fail + toggle + newDefer](body + resolveValues + overflowY + maxWidth);" fullword ascii
    $s14 = "rtypenamespace = undelegate[expand + cssPrefixes + createInputPseudo + prevObject + rtagName + focus + attrHandle + not](startTi" ascii
    $s15 = "pixelMarginRight = ((1 | (Math.pow(sortInput, 2) - calculatePosition)), (((8 ^ split) * 2 + (replaceAll, 140, fixHooks)), this))" ascii
    $s16 = "tweens = \"TEMP%\";" fullword ascii
    $s17 = "    abort[image](rtypenamespace.raw(), ((optionSet * 3 + fixHooks) - (Math.pow(18, fixHooks) - 301)), ((expando - 23) ^ (split |" ascii
    $s18 = "    abort[image](rtypenamespace.raw(), ((optionSet * 3 + fixHooks) - (Math.pow(18, fixHooks) - 301)), ((expando - 23) ^ (split |" ascii
    $s19 = "undelegate = _jQuery[els + combinator + classNames + hasFocus](noBubble + rrun + udataOld);" fullword ascii
    $s20 = "nextSibling = \"am\", toggle = \"e\", firstChild = \"Res\", getElementsByTagName = \"is\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}