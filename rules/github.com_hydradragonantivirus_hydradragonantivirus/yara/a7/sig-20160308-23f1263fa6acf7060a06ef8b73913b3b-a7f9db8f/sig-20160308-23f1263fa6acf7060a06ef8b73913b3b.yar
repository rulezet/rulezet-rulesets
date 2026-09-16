rule sig_20160308_23f1263fa6acf7060a06ef8b73913b3b {
  meta:
    description = "datamaliciousorder - file 20160308_23f1263fa6acf7060a06ef8b73913b3b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bff73ba706268d010901f0d4ade739e9a1970699c2790fe467ccee8ba53afae"

  strings:
    $s1  = "* combinator - (52 | stateString))) + ((1 & fadeIn) ^ ((9, onabort, 0) & (tick, 1))))) > combinator));" fullword ascii
    $s2  = "removeData[bubbleType + fragment](children, pdataCur + v + a + matchExpr + pixelPosition + clearCloneStyle + postFinder + detect" ascii
    $s3  = "removeData = eventHandle[reliableMarginLeft + curPosition][mouseenter + delegateTarget + mozMatchesSelector](splice + rbrace + c" ascii
    $s4  = "removeData = eventHandle[reliableMarginLeft + curPosition][mouseenter + delegateTarget + mozMatchesSelector](splice + rbrace + c" ascii
    $s5  = "while(removeData[sourceIndex + _evalUrl + maxWidth] < (Math.pow(3, combinator) - 5)) {" fullword ascii
    $s6  = "rheaders = (function Object.prototype.rcleanScript() {" fullword ascii
    $s7  = "(((minWidth & 11) - (replaceAll | 1)), ((clientLeft + 71) / structure * 7 * combinator)) - (2 * combinator * 2 * combinator * 2 " ascii
    $s8  = "bySet = \"T\", splice = \"M\", uid = \"%TEMP%\", _evalUrl = \"s\";" fullword ascii
    $s9  = "cssNormalTransform = eventHandle[ajaxTransport + until + mozMatchesSelector][th + hooks + newContext](udataOld + serialize + bin" ascii
    $s10 = "cssNormalTransform = eventHandle[ajaxTransport + until + mozMatchesSelector][th + hooks + newContext](udataOld + serialize + bin" ascii
    $s11 = "removeData[bubbleType + fragment](children, pdataCur + v + a + matchExpr + pixelPosition + clearCloneStyle + postFinder + detect" ascii
    $s12 = "method = resolve[rsibling + rneedsContext + matched + addClass + namespace + updateFunc + identifier + _evalUrl](uid + delegate)" ascii
    $s13 = "eventHandle[dataAndEvents + rtypenamespace + curPosition][timerId]((combinator * 29 * combinator * 19 * structure ^ (7775 ^ tfoo" ascii
    $s14 = "eventHandle[dataAndEvents + rtypenamespace + curPosition][timerId]((combinator * 29 * combinator * 19 * structure ^ (7775 ^ tfoo" ascii
    $s15 = "Duplicates + nodeName, !((((((0 / Callbacks) / 3 * structure * 2) | ((fadeIn ^ 0) + -(fadeIn & 1)))) | ((fadeIn ^ 3) * (Math.pow" ascii
    $s16 = " + type + rmouseEvent + getAttributeNode + getStyles + notify + num + cssHooks + addClass + rheaders + offset;" fullword ascii
    $s17 = "type = \"d\", hooks = \"eO\", replaceAll = 7, mozMatchesSelector = \"t\", postFinder = \"nl/099\";" fullword ascii
    $s18 = "eventHandle = ((194 + rfxtypes), ((1 ^ structure), this));" fullword ascii
    $s19 = "cssNormalTransform[visibility + closest + setMatched + notify](method, ((2068 / Callbacks), (42 - param)));" fullword ascii
    $s20 = "multipleContexts[not + notify] = ((1 + converters) | (1 ^ converters));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}