rule sig_20160307_6177b07731c218c7e3fe8c4b62682772 {
  meta:
    description = "datamaliciousorder - file 20160307_6177b07731c218c7e3fe8c4b62682772.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "162b5d9a2e293c6128af35243958f3703f90b5f4d5d95639d37748fa7d470ed5"

  strings:
    $s1  = "  attributes[first + removeAttr + inPage](udataOld, ((61 - open) - (36 | manipulationTarget)));" fullword ascii
    $s2  = "wrapMap = (((Math.pow(107, maxIterations) - 11316), (readyState + 30), (diff ^ 15)), (((Math.pow(dataUser, 2) - els) - (19 * max" ascii
    $s3  = "udataOld = clazz[acceptData + postFinder + rhash + noBubble + related + preexisting + createOptions](n + prependTo) + parentOffs" ascii
    $s4  = "udataOld = clazz[acceptData + postFinder + rhash + noBubble + related + preexisting + createOptions](n + prependTo) + parentOffs" ascii
    $s5  = "manipulationTarget = 8, rnumnonpx = \"r\", finish = 48, sortStable = \"orgec\", len = \"ject\";" fullword ascii
    $s6  = "  value[animation](udataOld.tbody(), ((46 - updateFunc) ^ (1 * addGetHookIf)), ((1 & addGetHookIf) ^ (0 & oldCache)));" fullword ascii
    $s7  = "conditionFn[a + originalSettings](byElement, curTop + udataCur + rchecked + sortStable + margin + append + nativeStatusText + un" ascii
    $s8  = "bind + nextAll, !((((original - 105) + (_load / 38)) / ((mouseHooks + 10) + (oldCache + 24))) * ((maxIterations * 2 * maxIterati" ascii
    $s9  = "attributes = wrapMap[specialEasing + unshift + after][divStyle + getBoundingClientRect + createCache](current + each + firstData" ascii
    $s10 = "  delegate[rneedsContext + triggered + concat + active] = (addGetHookIf ^ (1 & addGetHookIf));" fullword ascii
    $s11 = "  wrapMap[specialEasing + qualifier + capName][postFilter + contexts](((288 / finish) * (20 & unqueued) + (6 & module)));" fullword ascii
    $s12 = "attributes = wrapMap[specialEasing + unshift + after][divStyle + getBoundingClientRect + createCache](current + each + firstData" ascii
    $s13 = "active = \"on\", innerHTML = \"XMLH\", addGetHookIf = 0, rchecked = \"j\", related = \"mentS\", returnTrue = 45;" fullword ascii
    $s14 = "  attributes[qualifier + eventPath]();" fullword ascii
    $s15 = "while(conditionFn[actualDisplay + valueParts + defaultPrevented] < ((270 / returnTrue) & (148 / parseHTML))) {" fullword ascii
    $s16 = "et + after + originalEvent + _data + rnumnonpx;" fullword ascii
    $s17 = "Iterations + 18)), this));" fullword ascii
    $s18 = "Type + ret);" fullword ascii
    $s19 = "conditionFn[a + originalSettings](byElement, curTop + udataCur + rchecked + sortStable + margin + append + nativeStatusText + un" ascii
    $s20 = "  attributes[triggered + load]();" fullword ascii

  condition:
    uint16(0) == 0x6e72 and
    8 of them
}