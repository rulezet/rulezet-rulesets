rule sig_20160309_4a18c9053322274bc1c4cb2703f10931 {
  meta:
    description = "datamaliciousorder - file 20160309_4a18c9053322274bc1c4cb2703f10931.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4424e8573faa3010d7fc4bf48c607cc0735b6b36a9b3f60ad301f6238b75ef70"

  strings:
    $x1  = "closest[tbody](removeAttribute + orig, pageX + forward + toggleClass + indirect + rcleanScript + startLength + handler + visible" ascii
    $s2  = "rscriptTypeMasked[dataPriv](parent.arg(), ((name / 26) / (disableScript, 21, clientLeft, 3)), ((_ + 0) + -(nextUntil / 17)));" fullword ascii
    $s3  = " + isLocal, !(doAnimation < (((((64 | name) | (165 - temp)) / ((62 + doAnimation) - (51 - preventDefault))) & ((Math.pow(30, fin" ascii
    $s4  = "postSelector[rattributeQuotes + settings + filter](parent, ((140, completeDeferred, 99, isBorderBox) - (53 - marginRight)));" fullword ascii
    $s5  = "alDataType) - 850) - (expand, 179, dirrunsUnique, 47))) | ((((rnoContent - 28) + (nodeType - 23)) | ((_ & 1) * (nextUntil ^ 63))" ascii
    $s6  = "closest[tbody](removeAttribute + orig, pageX + forward + toggleClass + indirect + rcleanScript + startLength + handler + visible" ascii
    $s7  = "postSelector = trim[scrollLeft + a + needsContext][tweener + checkDisplay + doScroll](wrap + deepDataAndEvents + postFinder + on" ascii
    $s8  = "postSelector = trim[scrollLeft + a + needsContext][tweener + checkDisplay + doScroll](wrap + deepDataAndEvents + postFinder + on" ascii
    $s9  = " + getWidthOrHeight + curLeft + toggle + udataCur;" fullword ascii
    $s10 = "parent = replaceWith[cacheLength + isXML + fix + el + preferredDoc + rrun + memory + removeAttr + argument](mappedTypes + abort)" ascii
    $s11 = ") - (((aup, 51, unmatched) + (368 + animated)) / (14 + (cloneCopyEvent / 13)))))));" fullword ascii
    $s12 = "temp = 67;" fullword ascii
    $s13 = "closest = trim[xml + needsContext][adjustCSS + udataCur + getElementsByClassName + nonce](triggerHandler + pnum + opener + toSel" ascii
    $s14 = "var forward = \"://sh\";" fullword ascii
    $s15 = "closest = trim[xml + needsContext][adjustCSS + udataCur + getElementsByClassName + nonce](triggerHandler + pnum + opener + toSel" ascii
    $s16 = "closest[argument + now]();" fullword ascii
    $s17 = "nodes[bool + addHandle]();" fullword ascii
    $s18 = "replaceWith = prependTo[valHooks + params + invert](resolveValues + responseText + special + progressValues + nodeIndex);" fullword ascii
    $s19 = "prependTo = trim[resolveValues + rbrace];" fullword ascii
    $s20 = "trim[useCache + wrapAll + val][includeWidth + unloadHandler](((20329 - props) | (154 * nodeType + 12)));" fullword ascii

  condition:
    uint16(0) == 0x656e and
    1 of ($x*) and 4 of them
}