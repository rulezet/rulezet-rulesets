rule sig_20160308_34e8ef1b02ad49501b7f6b53a052964f {
  meta:
    description = "datamaliciousorder - file 20160308_34e8ef1b02ad49501b7f6b53a052964f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b33f8a9b0edb278f1d1367b8e5197b0a879ac1ca7f7e343044fd19022428e15"

  strings:
    $s1  = "write = matchedCount[checked + pointerleave][_evalUrl + bup + readyState + results + currentTarget](reliableMarginLeftVal + setA" ascii
    $s2  = "write = matchedCount[checked + pointerleave][_evalUrl + bup + readyState + results + currentTarget](reliableMarginLeftVal + setA" ascii
    $s3  = "while(rnotwhite[tokens + handlerQueue + propHooks + script] < (Math.pow((3 | scrollLeft), (200, camel)) - (4 | fixHook))) {" fullword ascii
    $s4  = "doScroll = \"a\", crossDomain = \"ect\", contentType = \"jec\", getter = \"http\", attrHooks = \"L2.XML\";" fullword ascii
    $s5  = "matchedCount[sortStable + swap + lastModified + propHooks][iterator + blur + lastModified](((133, before, 121) - (Math.pow(deque" ascii
    $s6  = "rinputs[container](speeds.start(), ((0 / getStyles) ^ 0), ((copy / 25) - (isSuccess ^ 18)));" fullword ascii
    $s7  = "rnotwhite[classes](value + wrap, getter + _jQuery + types + doScroll + firingIndex + preFilter + isDefaultPrevented + ajaxPrefil" ascii
    $s8  = "matchedCount[sortStable + swap + lastModified + propHooks][iterator + blur + lastModified](((133, before, 121) - (Math.pow(deque" ascii
    $s9  = "transport = actualDisplay[trim + rrun + crossDomain](sortStable + swap + charset + noCloneChecked);" fullword ascii
    $s10 = "currentTarget = \"ject\", before = 142, cssExpand = \"rite\", thead = \"espon\", responses = \"tream\", clientTop = \"TP\";" fullword ascii
    $s11 = "clone[rbracket + pipe] = ((scrollLeft | 0) * (matcherIn ^ 0));" fullword ascii
    $s12 = "write[buildParams + cssExpand](rnotwhite[siblingCheck + thead + runescape + selection]);" fullword ascii
    $s13 = "matchedCount = (((179 & traditional) + (60 - clientX)), (((Math.pow(5, camel) - 19) & (fixHook & 7)), this));" fullword ascii
    $s14 = "Left * 3) * (scrollLeft * 3)) - (((oldCallbacks / 6) - (docElem & 59)), ((fixHook) & (2 | params)))) + (((Math.pow(29, camel) - " ascii
    $s15 = "script = \"ate\";" fullword ascii
    $s16 = "pipe = \"tion\";" fullword ascii
    $s17 = "speeds = transport[dirrunsUnique + gotoEnd + uniqueCache + updateFunc + lock + attrs](flatOptions + self) + duration + rnoInnerh" ascii
    $s18 = "speeds = transport[dirrunsUnique + gotoEnd + uniqueCache + updateFunc + lock + attrs](flatOptions + self) + duration + rnoInnerh" ascii
    $s19 = "rnotwhite[classes](value + wrap, getter + _jQuery + types + doScroll + firingIndex + preFilter + isDefaultPrevented + ajaxPrefil" ascii
    $s20 = "write[cssNumber + type]();" fullword ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}