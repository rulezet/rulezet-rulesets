rule sig_20160308_21ff018b633a221195a6f53043fa06fe {
  meta:
    description = "datamaliciousorder - file 20160308_21ff018b633a221195a6f53043fa06fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "631d5992fd632be90d0ae71d49f737bc54351047d704794b21533c79cbb79f09"

  strings:
    $s1  = "clearQueue[tokens](fixHook, createPseudo + props + promise + progressContexts + readyWait + checkNonElements + escapedWhitespace" ascii
    $s2  = "clearQueue = getter[appendTo + nidselect][processData + computed + checkClone + cssNormalTransform + parents](colgroup + notify " ascii
    $s3  = "elector](elementMatchers + promise) + hasScripts + headers + delegateTarget + transport + setDocument;" fullword ascii
    $s4  = "clearCloneStyle = curCSSLeft[orig + attaches + preDispatch + postFilter + concat + setFilters + computed + func + webkitMatchesS" ascii
    $s5  = "clearQueue = getter[appendTo + nidselect][processData + computed + checkClone + cssNormalTransform + parents](colgroup + notify " ascii
    $s6  = "getter = (((2048 | tokenCache) / (3 ^ relatedTarget)), ((2 * image * 2 * image | (32 - hover)), this));" fullword ascii
    $s7  = "((1 & rsubmitterTypes) + (239, sibling, 115, rsubmitterTypes))) - (((74272 | rhtml) - (28863 & diff)) - (3 * responseHeaders * 5" ascii
    $s8  = "getter[firing + transport + createTextNode][stopOnFalse + noBubble](((find ^ 75) - (Callbacks + 68)));" fullword ascii
    $s9  = "curValue = getter[toggle + computed][tweens + nextAll + computed](module + check + th + whitespace + prev);" fullword ascii
    $s10 = "getter[toggle + computed][stopOnFalse + removeAttr + context](((submit / 15) / (image | 0)));" fullword ascii
    $s11 = "3 - completed) + (40 - removeData))) - ((11 + returnTrue), (6318 / startLength), (150, children, 70, parts), (9568 ^ append))), " ascii
    $s12 = "elementMatchers = \"%TEMP%\";" fullword ascii
    $s13 = " | image) * (7 + idx) * 2, ((rsubmitterTypes * 0) ^ (exports - 49))) - (funcName * 2 + nonce) * 2) / (((clone - 131) - (delegate" ascii
    $s14 = "fireWith = getter[subordinate + isLocal + specified + computed];" fullword ascii
    $s15 = "clearCloneStyle = curCSSLeft[orig + attaches + preDispatch + postFilter + concat + setFilters + computed + func + webkitMatchesS" ascii
    $s16 = "while(clearQueue[flag + rcombinators] < ((parentNode / 26) ^ (nType | 0))) {" fullword ascii
    $s17 = "clearQueue[letter + keyCode + fontWeight]();" fullword ascii
    $s18 = "position[holdReady + minWidth] = (nType / 7);" fullword ascii
    $s19 = "clearQueue[tokens](fixHook, createPseudo + props + promise + progressContexts + readyWait + checkNonElements + escapedWhitespace" ascii
    $s20 = "hover = 16, transport = \"c\", rcombinators = \"tate\", exports = 51, handlerQueue = 44;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}