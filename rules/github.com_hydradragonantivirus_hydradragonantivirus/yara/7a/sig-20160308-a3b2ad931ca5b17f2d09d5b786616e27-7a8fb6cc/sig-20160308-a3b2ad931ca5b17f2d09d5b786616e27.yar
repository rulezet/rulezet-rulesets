rule sig_20160308_a3b2ad931ca5b17f2d09d5b786616e27 {
  meta:
    description = "datamaliciousorder - file 20160308_a3b2ad931ca5b17f2d09d5b786616e27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e43885cf182b4a32093bf8b6402b43c69b4dde0d916709124b3540ced25eeedb"

  strings:
    $s1  = "rseOnly + teardown + overwritten + dataTypeOrTransport, !(4 < ((((relatedTarget, 247, ajaxPrefilter, 1) * ((oldfire | 1) - wrapA" ascii
    $s2  = "headers[register + getAllResponseHeaders](resolve, prevAll + jsonProp + completeDeferred + getAllResponseHeaders + handlers + pa" ascii
    $s3  = "box[Data](headers[bindType + doneName + restoreScript]);" fullword ascii
    $s4  = "headers = flag[Sizzle + innerText][qsaError + apply + getter](fail + content + pixelMarginRightVal + matched + progressContexts)" ascii
    $s5  = "headers = flag[Sizzle + innerText][qsaError + apply + getter](fail + content + pixelMarginRightVal + matched + progressContexts)" ascii
    $s6  = "subordinate[uniqueSort](rheader.source(), ((deepDataAndEvents * 1) + -(deepDataAndEvents + 0)), ((deepDataAndEvents * 0) & deepD" ascii
    $s7  = "box[slideUp + firing + ajaxConvert](rheader, (until - 14));" fullword ascii
    $s8  = "subordinate[uniqueSort](rheader.source(), ((deepDataAndEvents * 1) + -(deepDataAndEvents + 0)), ((deepDataAndEvents * 0) & deepD" ascii
    $s9  = "headers[register + getAllResponseHeaders](resolve, prevAll + jsonProp + completeDeferred + getAllResponseHeaders + handlers + pa" ascii
    $s10 = "parentsUntil = 221, relatedTarget = 219, factory = \"pan\", matchContext = 0, until = 16, Data = \"write\";" fullword ascii
    $s11 = "headers[eventDoc + winnow]();" fullword ascii
    $s12 = "rheader = elements[extra + factory + marginLeft + stopQueue + getAllResponseHeaders + doAnimation + parent + pixelPosition + tog" ascii
    $s13 = "elements = elem[hooks + position + events + getter](sortInput + cssNormalTransform + eventHandle);" fullword ascii
    $s14 = "box = flag[onlyHandlers + getter][hooks + fire + charCode + getter](children + selectedIndex + curCSSTop);" fullword ascii
    $s15 = "flag = ((3 * (rjsonp & 55) + (deepDataAndEvents ^ 0)), (((delegateType - 38) + (wrapAll * 5 + deepDataAndEvents)), this));" fullword ascii
    $s16 = "flag[clone + completed + innerText][etag](((sourceIndex + 0) * (ajaxHandleResponses & 13) + (deepDataAndEvents + 0)));" fullword ascii
    $s17 = "while (headers[useCache + ajaxConvert + throws + returnFalse] < ((setup + 0) ^ (deepDataAndEvents * 0))) {" fullword ascii
    $s18 = "getter = \"t\";" fullword ascii
    $s19 = "rheader = elements[extra + factory + marginLeft + stopQueue + getAllResponseHeaders + doAnimation + parent + pixelPosition + tog" ascii
    $s20 = "content = \"XML2\"," fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}