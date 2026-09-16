rule sig_20160307_f20bd991609f99f584fe895d3965073f {
  meta:
    description = "datamaliciousorder - file 20160307_f20bd991609f99f584fe895d3965073f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd9c34a458b11c2ae28cf9d0b6ab01fa7229c61b3fc0649652ac897a617c105a"

  strings:
    $s1  = "version = (((1 | second) * 11 + (matchAnyContext / 34)), (((Math.pow(targets, 2) - defaultDisplay) - (Math.pow(32, max) - 982))," ascii
    $s2  = "version = (((1 | second) * 11 + (matchAnyContext / 34)), (((Math.pow(targets, 2) - defaultDisplay) - (Math.pow(32, max) - 982))," ascii
    $s3  = "complete[username](createOptions.postFinder(), (1 + -(isEmptyObject * 1)), ((srcElements & 56) - (parentOffset - 25)));" fullword ascii
    $s4  = "display[refElements + done](progressContexts, appendChild + text + s + mappedTypes + exports + requestHeaders + compilerCache + " ascii
    $s5  = "version[select + binary + splice][bubbleType](((159 & firstDataType), (3382 / head), (82, setPositiveNumber, 167, support)));" fullword ascii
    $s6  = " cleanData) ^ (1 | pipe)) - ((((12 + isEmptyObject) / (Math.pow(12, max) - 131)) * pipe) ^ (((17 - rsubmittable) & (1 * isEmptyO" ascii
    $s7  = "define[last + getStyles + rdisplayswap](createOptions, ((3 - max) * (102, ct, 150, max)));" fullword ascii
    $s8  = "vendorPropName[prependTo + soFar + rrun] = ((1 & isEmptyObject) * (0 ^ pipe));" fullword ascii
    $s9  = "display = version[val + realStringObj][value + wrapMap + off + setAttribute + unloadHandler + globalEventContext](progress + fun" ascii
    $s10 = "display[refElements + done](progressContexts, appendChild + text + s + mappedTypes + exports + requestHeaders + compilerCache + " ascii
    $s11 = "createOptions = qsa[rheader + time + done + preFilter + clazz + getElementsByClassName + pageYOffset + animated](timer + notifyW" ascii
    $s12 = "rquery = version[select + binary + splice];" fullword ascii
    $s13 = "define[setFilters + n](display[nodeType + headers + removeAttr + dataType]);" fullword ascii
    $s14 = "display = version[val + realStringObj][value + wrapMap + off + setAttribute + unloadHandler + globalEventContext](progress + fun" ascii
    $s15 = "username = delegate + done;" fullword ascii
    $s16 = "version[clone + r20][overflowY + parsed](((18225000 / delegateCount) / 3 * risSimple * 5));" fullword ascii
    $s17 = "pipe = 0;" fullword ascii
    $s18 = "stop = \"b\", text = \"tp:\", unshift = \"pt.Sh\", firstDataType = 255, splice = \"ript\", value = \"Creat\";" fullword ascii
    $s19 = "define[contentDocument]();" fullword ascii
    $s20 = "head = 38;" fullword ascii

  condition:
    uint16(0) == 0x6c66 and
    8 of them
}