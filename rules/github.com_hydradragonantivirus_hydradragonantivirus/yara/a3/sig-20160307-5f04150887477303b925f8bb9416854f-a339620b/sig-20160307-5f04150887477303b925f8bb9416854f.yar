rule sig_20160307_5f04150887477303b925f8bb9416854f {
  meta:
    description = "datamaliciousorder - file 20160307_5f04150887477303b925f8bb9416854f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "965b8d8d43a958bb07183a5751db8330a42af0b2559e41219d75aac2c683acd5"

  strings:
    $s1  = "unique[funescape + rCRLF](getBoundingClientRect + removeClass + Callbacks, temp + trigger + preDispatch + pageYOffset + firstEle" ascii
    $s2  = "after = dataTypeOrTransport[excess + defaultDisplay + getStyles + relative](rsibling + setDocument + temp + match + each);" fullword ascii
    $s3  = "rbuggyQSA = after[prefix + requestHeaders + rbuggyMatches + targets + extra + leadingRelative + marginRight](end + isHidden) + i" ascii
    $s4  = "rbuggyQSA = after[prefix + requestHeaders + rbuggyMatches + targets + extra + leadingRelative + marginRight](end + isHidden) + i" ascii
    $s5  = "unique[funescape + rCRLF](getBoundingClientRect + removeClass + Callbacks, temp + trigger + preDispatch + pageYOffset + firstEle" ascii
    $s6  = "mentChild + boxSizingReliableVal + round + password + boxSizingReliableVal + onabort + throws + event, !(9 < (((((l, 32, finalDa" ascii
    $s7  = "- 25) + (inspect * 3 + obj)) ^ ((2 + tabIndex) - (45 & isBorderBox))) + ((11 - namespaces) + -(1 * (responseType, 1)))))));" fullword ascii
    $s8  = "clientLeft = ((Math.pow((30 * obj + 9), (attrId ^ 3)) - (finalDataType ^ 4784)), (((Math.pow(setMatcher, 2) - namespaces) * (166" ascii
    $s9  = "mappedTypes[key + width](unique[run + opt + oldfire]);" fullword ascii
    $s10 = "mappedTypes[minWidth + operator]();" fullword ascii
    $s11 = "temp = \"h\";" fullword ascii
    $s12 = "mappedTypes[serialize + addEventListener]();" fullword ascii
    $s13 = "rlocalProtocol = \"cr\", oldfire = \"Body\", password = \"c\", nidselect = \"ct\";" fullword ascii
    $s14 = "mappedTypes[callbackExpect + removeProp + keyCode](rbuggyQSA, ((inspect + 4) - obj * 2 * obj));" fullword ascii
    $s15 = "responseType = 195, animate = \".Str\", requestHeaders = \"andEnv\", serialize = \"ope\", classNames = \"Creat\", run = \"Res\";" ascii
    $s16 = "while (unique[size + isDefaultPrevented] < ((tabIndex & 61) / (implementation + 3))) {" fullword ascii
    $s17 = "tabIndex = 44, size = \"read\", round = \"is\";" fullword ascii
    $s18 = "prefix = \"Exp\", operator = \"se\";" fullword ascii
    $s19 = ", obj) + (2 | method)), this));" fullword ascii
    $s20 = "clientLeft[stopped + el][nType + td]((obj * 43 ^ (showHide)));" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}