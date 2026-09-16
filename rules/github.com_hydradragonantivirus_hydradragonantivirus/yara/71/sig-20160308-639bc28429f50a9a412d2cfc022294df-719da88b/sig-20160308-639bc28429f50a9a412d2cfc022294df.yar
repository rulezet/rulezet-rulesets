rule sig_20160308_639bc28429f50a9a412d2cfc022294df {
  meta:
    description = "datamaliciousorder - file 20160308_639bc28429f50a9a412d2cfc022294df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d3907f5200ce45eae0c52fd73516d48090d01efa4df1ca2c3eb3ccd95a6b53"

  strings:
    $x1  = "selectors[simulate](always, compile + test + optSelected + maxIterations + sortStable + rcssNum + divStyle + adjusted + noConfli" ascii
    $s2  = "PI[guid + serializeArray][rlocalProtocol + test]((rcombinators / 27) * (resolveContexts & 3) * rmouseEvent * (Math.pow(4, relate" ascii
    $s3  = "ct + top + currentTarget + root + guaranteedUnique + clone + siblings + replaceChild + flatOptions, !(4 == (Math.pow((((relatedT" ascii
    $s4  = "animated[ajaxSetup + win + prevAll + url](uniqueSort, ((delegateType & 29) - relatedTarget * 13));" fullword ascii
    $s5  = "dTarget) - 11) * (relatedTarget & 3) * (relatedTarget * 2 + Data) * 2 * (resolveContexts + 2));" fullword ascii
    $s6  = "t | 0)))), ((((Data + -1) | (actualDisplay, 170, sort, 26)) | (Math.pow(parent, 2) - scriptCharset) * (1 + Data)) - (((701 & loa" ascii
    $s7  = "    PI[guid + settings + curElem][rlocalProtocol + test](((Math.pow(2038, relatedTarget) - 4149844) / relatedTarget * 3 * relate" ascii
    $s8  = "    PI[guid + settings + curElem][rlocalProtocol + test](((Math.pow(2038, relatedTarget) - 4149844) / relatedTarget * 3 * relate" ascii
    $s9  = "d) / (11 * resolveContexts + 8)) + ((Math.pow(rmouseEvent, 2) - results) & (60 - sort))))) - ((((0 ^ Data) * (1 + XMLHttpRequest" ascii
    $s10 = "animated = PI[rdisplayswap + mappedTypes + curElem][selectedIndex + dispatch + focusin](insertBefore + script + namespace);" fullword ascii
    $s11 = ")) + -((13 & compilerCache) - (1 * isPropagationStopped))) ^ ((Math.pow((1 * resolveContexts), 2) - (Data * 4)) & (Math.pow((s -" ascii
    $s12 = "PI[guid + serializeArray][rlocalProtocol + test]((rcombinators / 27) * (resolveContexts & 3) * rmouseEvent * (Math.pow(4, relate" ascii
    $s13 = "script = \"DB.Str\", doc = \"ring\", cloneCopyEvent = \"MSXML\", soFar = 44, focusin = \"ct\", isDefaultPrevented = \"Run\";" fullword ascii
    $s14 = "subordinate[anim](uniqueSort.cleanData(), (Data * 0), (Data + -1));" fullword ascii
    $s15 = "selectors[simulate](always, compile + test + optSelected + maxIterations + sortStable + rcssNum + divStyle + adjusted + noConfli" ascii
    $s16 = "while(selectors[elementMatcher + idx + ajaxConvert + curCSSTop] < ((6 & rmouseEvent) | (4 & option))) {" fullword ascii
    $s17 = "defineProperty = \"Obj\", url = \"e\", compile = \"htt\", adjusted = \".\", parent = 10, XMLHttpRequest = 0;" fullword ascii
    $s18 = "requestHeaders = \"ion\", Data = 1;" fullword ascii
    $s19 = "var always = \"GET\"," fullword ascii
    $s20 = "PI = (((8 | results) ^ (854 / option)), (((4 & option) * (2 & resolveContexts) + (1 * Data)), this));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}