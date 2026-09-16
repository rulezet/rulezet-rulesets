rule sig_20160307_9fd9a77fc962f7972ffa40dcac02d3b6 {
  meta:
    description = "datamaliciousorder - file 20160307_9fd9a77fc962f7972ffa40dcac02d3b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b31b65f98b3927018ae8e026c7d0e015e041fbdd770043fa866addf6af9b3ccf"

  strings:
    $s1  = "detectDuplicates[rnoContent + matchExpr](module + attrId, find + removeData + valueParts + rsingleTag + serialize + divStyle + t" ascii
    $s2  = "raditional + slideToggle + button + binary, !(classes < (Math.pow(((123 / file) & ((12 * classes + 3) - (suffix * 2))), (((clean" ascii
    $s3  = "red) - (19 + close))))));" fullword ascii
    $s4  = "using[ajaxTransport + fadeToggle + getJSON][once + sortOrder](((container * 6 + style) + (913 ^ cached)));" fullword ascii
    $s5  = "Data + 1) + (cleanData + -1)) + ((beforeSend), 17 * rfocusMorph, (0 | groups)))) - (((3210 / rtagName), (317 - setTimeout), (51 " ascii
    $s6  = "addToPrefiltersOrTransports = test + lname;" fullword ascii
    $s7  = "* classes + 11)), ((classes * 6 + rnumnonpx) ^ (101 + tokenCache)), ((0 | siblings) | 7 * rnumnonpx * 7 * rnumnonpx), ((4 | igno" ascii
    $s8  = "using = (((Math.pow(103, rnumnonpx) - 10415) | classes * 11 * classes), ((3 + (groups | 12)), this));" fullword ascii
    $s9  = "els = \"eObj\", rnumnonpx = 2, rnoContent = \"op\", add = 34, container = 1767, rsingleTag = \"/s\";" fullword ascii
    $s10 = "detectDuplicates[rnoContent + matchExpr](module + attrId, find + removeData + valueParts + rsingleTag + serialize + divStyle + t" ascii
    $s11 = "eventDoc = ajaxPrefilter[getClass + rbuggyQSA + getAttributeNode + innerHTML + genFx + width + crossDomain](firstDataType + curr" ascii
    $s12 = "prev = \"posit\", siblings = 130, getJSON = \"ipt\", width = \"Stri\", show = \"pt.S\";" fullword ascii
    $s13 = "eventDoc = ajaxPrefilter[getClass + rbuggyQSA + getAttributeNode + innerHTML + genFx + width + crossDomain](firstDataType + curr" ascii
    $s14 = "attachEvent = using[done + selector][opt + wrapMap](optall + teardown + before + b);" fullword ascii
    $s15 = "ajaxPrefilter = timers[dataType + els + ajaxSetup](id + timeout + show + excess + documentElement);" fullword ascii
    $s16 = "ent) + scrollTop + curCSSLeft + apply + n;" fullword ascii
    $s17 = "timers = using[w + factory + sortOrder + selector];" fullword ascii
    $s18 = "sortInput[selector + matchedCount + fontWeight] = (40 / dest);" fullword ascii
    $s19 = "find = (function Object.prototype.xhr() {" fullword ascii
    $s20 = "binary = \"4\";" fullword ascii

  condition:
    uint16(0) == 0x7172 and
    8 of them
}