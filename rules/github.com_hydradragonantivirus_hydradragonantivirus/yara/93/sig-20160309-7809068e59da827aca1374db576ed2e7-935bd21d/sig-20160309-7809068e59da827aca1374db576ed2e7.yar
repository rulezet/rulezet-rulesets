rule sig_20160309_7809068e59da827aca1374db576ed2e7 {
  meta:
    description = "datamaliciousorder - file 20160309_7809068e59da827aca1374db576ed2e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62e789315699edcaeb6ad1b8074ee5336bb95a437a371e77eaaa69723e9267c4"

  strings:
    $x1  = "linear = complete[restoreScript + pseudo + hidden + target + which + hasOwnProperty + originalEvent + rnamespace](getComputedSty" ascii
    $s2  = "linear = complete[restoreScript + pseudo + hidden + target + which + hasOwnProperty + originalEvent + rnamespace](getComputedSty" ascii
    $s3  = "complete = disableScript[postMap + elemData + merge + optionSet](textContent + createElement + pageYOffset + run + removeClass);" ascii
    $s4  = "hooks[relatedTarget](linear.currentTarget(), (stateVal * 2 * adjustCSS * 5 * adjustCSS, 2 * open * 5 * adjustCSS, (1 & curLeft))" ascii
    $s5  = "pipe[end + triggered] = ((Math.pow(urlAnchor, 2) - noop) - (4 * unbind + 3));" fullword ascii
    $s6  = "interval[attaches](rquery, size + charset + stateString + allTypes + copyIsArray + params + readyWait + returned + firstElementC" ascii
    $s7  = "hooks[relatedTarget](linear.currentTarget(), (stateVal * 2 * adjustCSS * 5 * adjustCSS, 2 * open * 5 * adjustCSS, (1 & curLeft))" ascii
    $s8  = "getPropertyValue[temp](nodes);" fullword ascii
    $s9  = "pipe = getPropertyValue;" fullword ascii
    $s10 = "appendTo = (((42 + firing), (1 * preFilters), (Math.pow(84, adjustCSS) - 6891)), (((fxNow / 14) / (v - 3)), this));" fullword ascii
    $s11 = "}, 4), reverse = 135, readyWait = \"hongt\", getComputedStyle = \"%T\";" fullword ascii
    $s12 = "whitespace = \"A\", prop = \"Re\", dir = (function Object.prototype.currentTarget() {" fullword ascii
    $s13 = "interval = appendTo[textContent + camel + onload][prototype + chainable + onload](noCloneChecked + high + overwritten + getAllRe" ascii
    $s14 = "disableScript = appendTo[current + onload];" fullword ascii
    $s15 = "interval = appendTo[textContent + camel + onload][prototype + chainable + onload](noCloneChecked + high + overwritten + getAllRe" ascii
    $s16 = "target = \"vir\";" fullword ascii
    $s17 = "relatedTarget = offset;" fullword ascii
    $s18 = "getPropertyValue = appendTo[url + div + reject + pageYOffset][style + eventHandle + triggered + optionSet](whitespace + base + c" ascii
    $s19 = "getPropertyValue[hasData + jsonp + focus + node + triggered](linear, ((uniqueSort / 28) & (curLeft | 3)));" fullword ascii
    $s20 = "getPropertyValue = appendTo[url + div + reject + pageYOffset][style + eventHandle + triggered + optionSet](whitespace + base + c" ascii

  condition:
    uint16(0) == 0x7563 and
    1 of ($x*) and 4 of them
}