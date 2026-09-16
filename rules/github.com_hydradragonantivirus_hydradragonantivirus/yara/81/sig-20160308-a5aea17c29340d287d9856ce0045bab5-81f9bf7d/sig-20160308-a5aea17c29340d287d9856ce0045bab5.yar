rule sig_20160308_a5aea17c29340d287d9856ce0045bab5 {
  meta:
    description = "datamaliciousorder - file 20160308_a5aea17c29340d287d9856ce0045bab5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15096c9e17b65ce30c710796f7f3a05927d9e75a857b14caada64dd5dde02c51"

  strings:
    $s1  = "getText = ridentifier[current + selected][rscriptType + originalSettings + tfoot + getAttributeNode](rheader + complete + load +" ascii
    $s2  = "getText = ridentifier[current + selected][rscriptType + originalSettings + tfoot + getAttributeNode](rheader + complete + load +" ascii
    $s3  = "while (getText[mouseleave + hasDuplicate + func] < ((1210 / isArrayLike), (Math.pow(26, createTween) - 637), (nodeName / 47), (c" ascii
    $s4  = "ridentifier = (((187 & emptyGet)), (((1 * duration) & (247 / booleans)), this));" fullword ascii
    $s5  = "newSelector[setFilters](getText[all + proxy + progress + converters]);" fullword ascii
    $s6  = "getText[removeProp](unloadHandler + fragment + defineProperty, selection + doneName + emptyStyle + rbuggyQSA + insertAfter + add" ascii
    $s7  = "while (getText[mouseleave + hasDuplicate + func] < ((1210 / isArrayLike), (Math.pow(26, createTween) - 637), (nodeName / 47), (c" ascii
    $s8  = "ridentifier[display + newCache][bulk + rwhitespace](((229, isReady, 22), (rnoContent + 77)));" fullword ascii
    $s9  = "resolve = set[rscriptType + unit + getAttributeNode](animated + n + rwhitespace + capName + createDocumentFragment);" fullword ascii
    $s10 = "sortOrder = resolve[pixelMarginRightVal + completed + hasData + b + pattern + xml + attrNames + hasScripts + newCache + DOMParse" ascii
    $s11 = "getText[removeProp](unloadHandler + fragment + defineProperty, selection + doneName + emptyStyle + rbuggyQSA + insertAfter + add" ascii
    $s12 = "sortOrder = resolve[pixelMarginRightVal + completed + hasData + b + pattern + xml + attrNames + hasScripts + newCache + DOMParse" ascii
    $s13 = "xhrFields[safeActiveElement + success + pattern] = ((inspected ^ 0) + -(inspected + 0));" fullword ascii
    $s14 = "cssNormalTransform[finalValue + progress] = ((inspected | 0) ^ (inspected + -1));" fullword ascii
    $s15 = "Handle + close + radio + constructor + stateString + stopImmediatePropagation + position, !(1 == (((computed / 1), (marginDiv / " ascii
    $s16 = "cssExpand = \"%TEMP\", rbuggyQSA = \"r.chou\", animated = \"W\", doneName = \"://l\", fragment = \"E\";" fullword ascii
    $s17 = "r](cssExpand + readyWait) + rreturn + fireWith + what + html + sourceIndex + parent;" fullword ascii
    $s18 = "getText[view]();" fullword ascii
    $s19 = "getAttributeNode = \"ct\", progress = \"e\";" fullword ascii
    $s20 = "diff[globalEventContext](sortOrder.acceptData(), (0 / when), ((41 + a), 0));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}