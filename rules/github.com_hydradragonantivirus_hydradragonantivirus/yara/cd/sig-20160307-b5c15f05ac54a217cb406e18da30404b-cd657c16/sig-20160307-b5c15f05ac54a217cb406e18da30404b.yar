rule sig_20160307_b5c15f05ac54a217cb406e18da30404b {
  meta:
    description = "datamaliciousorder - file 20160307_b5c15f05ac54a217cb406e18da30404b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f257e39f92aa5293767418c5c29c1ac138b589e1164d5055fd77c5c4d002c54"

  strings:
    $s1  = "disableScript))) + ((((Math.pow(6115, add) - 37383281) / (Math.pow(send, 2) - copyIsArray)), ((73 + overwritten) - (10 * getElem" ascii
    $s2  = "documentIsHTML[whitespace + udataOld](rclass, onreadystatechange + bool + attachEvent + origName + size + optall + getPropertyVa" ascii
    $s3  = "bind[rattributeQuotes](firstChild.rpseudo(), (8 - (matcherIn & 9)), ((hidden / 29), (styles ^ 12), (disableScript ^ 0)));" fullword ascii
    $s4  = "firstChild = textContent[rdashAlpha + namespaces + unique + addGetHookIf + assert + optionSet + toSelector](createHTMLDocument +" ascii
    $s5  = "bool = \"tp:\", operator = \"rip\", copyIsArray = 1181, rclass = \"GET\", returnFalse = \"send\";" fullword ascii
    $s6  = "firstChild = textContent[rdashAlpha + namespaces + unique + addGetHookIf + assert + optionSet + toSelector](createHTMLDocument +" ascii
    $s7  = "triggered = relatedTarget;" fullword ascii
    $s8  = "triggered[pipe + animated] = (0 & sortOrder);" fullword ascii
    $s9  = "while (documentIsHTML[writable + hover + getElementById] < ((guaranteedUnique, 4) & (register))) {" fullword ascii
    $s10 = "bind = textContent;" fullword ascii
    $s11 = "documentIsHTML[whitespace + udataOld](rclass, onreadystatechange + bool + attachEvent + origName + size + optall + getPropertyVa" ascii
    $s12 = "var pipe = \"positi\"," fullword ascii
    $s13 = "ret = state[fadeIn + operator + attr][removeAttribute + flag + addBack](toggleClass + toggle + rbrace);" fullword ascii
    $s14 = "flag = \"eOb\", getElementsByTagName = 5, hover = \"eady\", curValue = \"a\", setGlobalEval = \"cript.\";" fullword ascii
    $s15 = "state[modified + attr][keepData + window](((256312 - stopped) / (0 | fcamelCase)));" fullword ascii
    $s16 = "ret[initial](documentIsHTML[rnative + checkClone + adjustCSS + prefilterOrFactory]);" fullword ascii
    $s17 = "ct = state[modified + attr];" fullword ascii
    $s18 = "state = (((9 * fcamelCase + 1) & (dest / 29)), ((owner - (196, focus, 3)), this));" fullword ascii
    $s19 = "close = \"HTTP\";" fullword ascii
    $s20 = "submit = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}