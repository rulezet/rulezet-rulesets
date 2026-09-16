rule sig_20160307_526b5fdca07bf2657d9905bc60535a40 {
  meta:
    description = "datamaliciousorder - file 20160307_526b5fdca07bf2657d9905bc60535a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5740c1cb4980979eea1fa54a7e78fe14ed8672dde48785900ddb23781d704d89"

  strings:
    $x1  = "num[setAttribute](processData.ofType(), ((getWindow / 4) + -hasData), ((0 ^ operator) / (36 / hasData)));" fullword ascii
    $s2  = "processData = seed[fxNow + ifModified + classCache + selection + check + addClass + hover + elems + capName](createElement + twe" ascii
    $s3  = "what[readyList + getPropertyValue] = ((hasData + -1) & (operator | 0));" fullword ascii
    $s4  = "hidden[handlerQueue](responseType + fadeIn, cors + trim + opacity + ajaxConvert + _jQuery + addToPrefiltersOrTransports + unit +" ascii
    $s5  = " clearTimeout + raw, !(((Math.pow((((matcherOut / 40) - (slideToggle | 8)) - ((checked + 226) / (getWindow * 6 + noConflict))), " ascii
    $s6  = "en + getBoundingClientRect) + relative + reject + hasContent + origName;" fullword ascii
    $s7  = "rfocusable[success + getAttribute][currentTarget + document](((serializeArray | 132) / (open & 9)));" fullword ascii
    $s8  = "ts))), ((43 / ajax) ^ ((1 + noConflict) & (1 * apply)))) - (((53 & head) - (1120 / show)) ^ (206, noConflict) * (577 - display))" ascii
    $s9  = "(((2 & apply) & (58 / conv2)) + ((0 / postMap) ^ (1 + -hasData)))) - ((2067 / newSelector) * (6 + handlers) - ((35, namespaces) " ascii
    $s10 = "compareDocumentPosition[getElementsByName + unique]();" fullword ascii
    $s11 = "rfocusable = ((7 * ready & 217), (((hasData | 0) ^ (border - 33)), this));" fullword ascii
    $s12 = "processData = seed[fxNow + ifModified + classCache + selection + check + addClass + hover + elems + capName](createElement + twe" ascii
    $s13 = "& 29 * handlers))) - (Math.pow(((23 - implementation) * (399 / run) - ((2046 / list), (9 | code), (157 ^ outerCache), (924 / par" ascii
    $s14 = "max = \"teOb\", origName = \".scr\", prependTo = \".\", show = 35, run = 21;" fullword ascii
    $s15 = "matchesSelector = rfocusable[success + getAttribute];" fullword ascii
    $s16 = "compareDocumentPosition = rfocusable[success + getAttribute][parse + pos + preDispatch](fn + abort + opts + camelCase + all + fl" ascii
    $s17 = "rfocusable[createHTMLDocument + height][boxSizingReliable](((jQuery & 27583) - (mozMatchesSelector / 3)));" fullword ascii
    $s18 = "compareDocumentPosition = rfocusable[success + getAttribute][parse + pos + preDispatch](fn + abort + opts + camelCase + all + fl" ascii
    $s19 = "checked = 1048, getElementsByName = \"cl\", cors = \"http:/\";" fullword ascii
    $s20 = "compareDocumentPosition[originAnchor](hidden[cssExpand + sortOrder + resolveContexts + fontWeight]);" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    1 of ($x*) and 4 of them
}