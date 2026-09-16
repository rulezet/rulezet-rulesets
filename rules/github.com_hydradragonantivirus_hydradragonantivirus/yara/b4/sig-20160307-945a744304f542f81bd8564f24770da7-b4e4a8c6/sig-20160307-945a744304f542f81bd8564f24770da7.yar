rule sig_20160307_945a744304f542f81bd8564f24770da7 {
  meta:
    description = "datamaliciousorder - file 20160307_945a744304f542f81bd8564f24770da7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a5177aa0ee01a0e31917c372ebe4b7b26b677ac052917e2d67d7073eb7112b"

  strings:
    $s1  = "filters[getById](_load + callback, getBoundingClientRect + attributes + parseOnly + animate + always + createButtonPseudo + genF" ascii
    $s2  = "timeout[id + adjustCSS + input][inArray + hasContent](((1829 & documentIsHTML) * (34 - related) + (Math.pow(535, transports) - 2" ascii
    $s3  = "timeout[id + adjustCSS + input][inArray + hasContent](((1829 & documentIsHTML) * (34 - related) + (Math.pow(535, transports) - 2" ascii
    $s4  = "filters = timeout[mouseenter + locked + input][document + currentTarget + ready](postFinder + inArray + letterSpacing + tweens +" ascii
    $s5  = "filters = timeout[mouseenter + locked + input][document + currentTarget + ready](postFinder + inArray + letterSpacing + tweens +" ascii
    $s6  = " ((881 - restoreScript) / (5 * token + 3))) + (Math.pow(((oldCache * 2 + stored), (2 + fast)), ((27 / isWindow) ^ (150 / dest)))" ascii
    $s7  = "x, !((((((72 & special) | (Math.pow(145, transports) - 20765)) / ((end & 25) ^ (fragment, 144, elemdisplay, 61))) + (Math.pow((f" ascii
    $s8  = "simple = timeout[requestHeaders + opacity + exports];" fullword ascii
    $s9  = "ast + (33 / set)), ((1 * fast) & (10 / attrHandle))) - ((0 / cssExpand) | 10))) & ((((Math.pow(set, 2) - aup) - (43 - string)) -" ascii
    $s10 = "isWindow = 27, rheader = \"Script\", open = 0;" fullword ascii
    $s11 = "to = timeout[id + exports][nextUntil + onreadystatechange + opener](hidden + len + isXML + nextSibling + attachEvent + wrapMap);" ascii
    $s12 = "startLength = \"d\", replaceWith = \"TEMP%/\", onreadystatechange = \"teOb\", responseType = \".s\", checkDisplay = \"s\", unshi" ascii
    $s13 = "pseudos = simple[ajaxPrefilter + fixInput + rchecked + ready](id + exports + factory + multipleContexts);" fullword ascii
    $s14 = "to[collection + ownerDocument](filters[onerror + checkDisplay + options + ridentifier + preFilters]);" fullword ascii
    $s15 = "timeout[htmlPrefilter + rheader][createTextNode + adjustCSS](((9 ^ string) + (66 ^ firstElementChild)));" fullword ascii
    $s16 = "outermostContext[linear] = ((refElements | 1) + (refElements + -1));" fullword ascii
    $s17 = "stopPropagation[rdashAlpha](keepData.active(), (open / 37), ((stored - 12) & (cssExpand, 1)));" fullword ascii
    $s18 = "fast = 3, body = 7, special = 101, rtrim = \"e\", getById = \"open\", factory = \".Shel\";" fullword ascii
    $s19 = "filters[getById](_load + callback, getBoundingClientRect + attributes + parseOnly + animate + always + createButtonPseudo + genF" ascii
    $s20 = "to[nodes + disable]();" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}