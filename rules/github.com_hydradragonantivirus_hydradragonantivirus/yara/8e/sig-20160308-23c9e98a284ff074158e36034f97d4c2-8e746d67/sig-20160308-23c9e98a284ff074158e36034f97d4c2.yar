rule sig_20160308_23c9e98a284ff074158e36034f97d4c2 {
  meta:
    description = "datamaliciousorder - file 20160308_23c9e98a284ff074158e36034f97d4c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6cbc601b437e4f4668cb6d9d30cf8030f2635067f072b0752ab4b69f240a34e"

  strings:
    $s1  = "requestHeaders[compare](marginRight, swing + matchExpr + ifModified + matchAnyContext + show + origName + set + top, !((((((isPl" ascii
    $s2  = "index[curLeft + setFilters + _default](scripts, ((Math.pow(76, stopQueue) - 5682) / (step / 26)));" fullword ascii
    $s3  = "scripts = createPseudo[prevUntil + disable + attributes + dataTypeExpression + i + isFunction + returned](overrideMimeType + url" ascii
    $s4  = "scripts = createPseudo[prevUntil + disable + attributes + dataTypeExpression + i + isFunction + returned](overrideMimeType + url" ascii
    $s5  = "createPseudo = doc[idx + dataUser + remove + content](obj + clearCloneStyle + fromCharCode);" fullword ascii
    $s6  = "while(requestHeaders[rjsonp + prop + val + classNames] < ((64, progress, 154, contains) | (Math.pow(3, stopQueue) - 5))) {" fullword ascii
    $s7  = "requestHeaders[compare](marginRight, swing + matchExpr + ifModified + matchAnyContext + show + origName + set + top, !((((((isPl" ascii
    $s8  = "ified / 3) | (Math.pow(propName, 2) - unmatched)))) - (((44 - maxWidth) / (1 * until)) | (Math.pow(((Math.pow(6, stopQueue) - 29" ascii
    $s9  = " | 3)) ^ ((Math.pow(contains, 2) - pixelPosition) + 2 * selected)) + (((18 ^ state) & (63 * stopQueue + 52)), ((register / 2) * " ascii
    $s10 = "Anchor + classes + origName) + parent + hasFocus + restoreScript + appendChild + setRequestHeader + fadeIn + rjsonp + tweeners +" ascii
    $s11 = "attrHandle[addEventListener + view] = (4 - contains);" fullword ascii
    $s12 = "index[disableScript + prototype + appendChild]();" fullword ascii
    $s13 = "requestHeaders = funescape[obj + compilerCache + opener][serializeArray + props + winnow + elementMatcher](rreturn + postSelecto" ascii
    $s14 = "requestHeaders = funescape[obj + compilerCache + opener][serializeArray + props + winnow + elementMatcher](rreturn + postSelecto" ascii
    $s15 = "funescape[uniqueSort + getAll][mozMatchesSelector + guid](((high / 6) + (when, 47, root, 36)));" fullword ascii
    $s16 = "ainObject - 29) * (lastModified ^ 1)) | ((lastModified ^ 1) | (lastModified | 0))) ^ (((_load ^ 488) | (self | 272)) / ((lastMod" ascii
    $s17 = "funescape = ((269 * stopQueue * 2 * stopQueue / (8 | lastModified)), ((Math.pow(11, stopQueue) - 102), this));" fullword ascii
    $s18 = "(xml * 2) + (lastModified | 4)))) / (Math.pow(((reliableMarginLeft ^ 8) & (until | 20)), ((lastModified ^ 0) | (lastModified ^ 2" ascii
    $s19 = "_removeData[firingIndex + prototype] = ((holdReady & 12) / stopQueue * 3 * stopQueue);" fullword ascii
    $s20 = "argument[apply](scripts.toggle(), (lastModified / 47), ((lastModified | 0) ^ (lastModified | 0)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}