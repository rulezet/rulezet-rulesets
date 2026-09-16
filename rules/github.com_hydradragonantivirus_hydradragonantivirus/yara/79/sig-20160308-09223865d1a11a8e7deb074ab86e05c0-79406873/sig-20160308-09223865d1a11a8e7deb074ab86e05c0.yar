rule sig_20160308_09223865d1a11a8e7deb074ab86e05c0 {
  meta:
    description = "datamaliciousorder - file 20160308_09223865d1a11a8e7deb074ab86e05c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ef4faf5fac23ef00f851e45ecbe1d99234a2571c5f4355de4c82d59f071a12"

  strings:
    $x1  = "focusin[teardown + andSelf](responseType, stored + isSimulated + write + charset + nid + selectors + aup + createTween + accepts" ascii
    $s2  = " + getWindow + pipe + tick + next + on + createElement, !((((((27 + mozMatchesSelector) ^ (1 ^ manipulationTarget)), (1 + (ret -" ascii
    $s3  = "swap[rheaders + hasData + getComputedStyle + n][transport + each + fixInput + selector](((1862 / cssExpand) * (4 / parsed) + (80" ascii
    $s4  = "swap[Sizzle + getComputedStyle + n][lname + obj](((24150 / inspect) - (Math.pow(7635, parsed) - 58284075)));" fullword ascii
    $s5  = "swap[rheaders + hasData + getComputedStyle + n][transport + each + fixInput + selector](((1862 / cssExpand) * (4 / parsed) + (80" ascii
    $s6  = "document = rnoInnerhtml[callbackInverse + isLocal + responseHeaders + code + hold + defaultValue + textContent](top + createText" ascii
    $s7  = "document = rnoInnerhtml[callbackInverse + isLocal + responseHeaders + code + hold + defaultValue + textContent](top + createText" ascii
    $s8  = "groups[getElementsByName + what] = (matcherFromTokens / (5 * old + 4));" fullword ascii
    $s9  = " 3))) + -(((matcherFromTokens | 1) | (inspect)) | ((1 & inspect) + (1 + -inspect)))) ^ ((((5 ^ parsed) | (36 / arr)) + ((5 / deq" ascii
    $s10 = "top = \"%TEMP%\";" fullword ascii
    $s11 = "focusin = swap[Sizzle + parentNode][getElementsByTagName + isWindow + rclickable](fromCharCode + e + async + ajaxHandleResponses" ascii
    $s12 = "focusin = swap[Sizzle + parentNode][getElementsByTagName + isWindow + rclickable](fromCharCode + e + async + ajaxHandleResponses" ascii
    $s13 = "rnoInnerhtml = body[getElementsByTagName + cssNormalTransform + ajaxSetup](Sizzle + parentNode + dataFilter + each);" fullword ascii
    $s14 = "swap = (((46 * ret + 22), (arr * 17 + parsed)), (((59 - cssExpand) + (1 + unwrap)), this));" fullword ascii
    $s15 = "createTween = \"ti\", emptyGet = \".scr\", matcherIn = \"saveT\", old = 4, Sizzle = \"WScr\", callbackInverse = \"Exp\";" fullword ascii
    $s16 = "nType[dataTypeExpression + nid] = ((matcherFromTokens & 0) | (inspect ^ 0));" fullword ascii
    $s17 = "pipe = \"98\";" fullword ascii
    $s18 = "textContent = \"ngs\", fromCharCode = \"MSXML2\", wrap = \"y\", hold = \"nmentS\", obj = \"ep\";" fullword ascii
    $s19 = "Node) + stateString + escapedWhitespace + emptyGet;" fullword ascii
    $s20 = "expando[unloadHandler + undelegate + memory + nid]();" fullword ascii

  condition:
    uint16(0) == 0x7274 and
    1 of ($x*) and 4 of them
}