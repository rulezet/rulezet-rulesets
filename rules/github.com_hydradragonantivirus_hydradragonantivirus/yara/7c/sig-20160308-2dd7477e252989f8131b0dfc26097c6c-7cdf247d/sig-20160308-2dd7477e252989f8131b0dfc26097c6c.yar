rule sig_20160308_2dd7477e252989f8131b0dfc26097c6c {
  meta:
    description = "datamaliciousorder - file 20160308_2dd7477e252989f8131b0dfc26097c6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a6ec9af8ee6f668f08ac19120e658811a67d6922edbd1f11019f9ebd1a44a4c"

  strings:
    $s1  = "ajaxTransport[delegate + mouseHooks](addGetHookIf, hasContent + getText + cleanData + url + inspected + copy + finish + event + " ascii
    $s2  = "version = letter[global + curValue][rnoContent + results + clearQueue + getJSON](parentOffset + wrapAll + to);" fullword ascii
    $s3  = "ajaxTransport[delegate + mouseHooks](addGetHookIf, hasContent + getText + cleanData + url + inspected + copy + finish + event + " ascii
    $s4  = "letter[hide + responseHeadersString][currentTarget](((375000 / marginLeft) & (8580 | nativeStatusText)));" fullword ascii
    $s5  = " letter[hide + currentValue + makeArray + urlAnchor][createInputPseudo + finalText](((14 + curPosition) ^ (684 / manipulationTar" ascii
    $s6  = "ajaxTransport = letter[hide + currentValue + curValue][curLeft + returnValue + document](run + els + tag + compile + tuples);" fullword ascii
    $s7  = "version[status + all + getById](eventPath, ((push_native + 0) + rprotocol));" fullword ascii
    $s8  = "eventPath = dataFilter[rbrace + condense + props + currentValue + current + bindType + crossDomain + status](isReady + currentTi" ascii
    $s9  = "eventPath = dataFilter[rbrace + condense + props + currentValue + current + bindType + crossDomain + status](isReady + currentTi" ascii
    $s10 = "version[tokenize + escaped](ajaxTransport[parseJSON + parents + responseType]);" fullword ascii
    $s11 = "dataFilter = matches[returnFalse + urlAnchor + constructor + getJSON](hide + appendTo + fxNow + parseOnly);" fullword ascii
    $s12 = "t) | 5), push_native) - ((98 | defineProperty) * (1 * handle) + (109 & fn))) ^ (((28 & splice) + (10 * push_native + 1)) | ((css" ascii
    $s13 = "letter = (((1 + traditional) * (12 + getElementsByClassName) + (10 ^ ignored)), (((11 + getElementsByClassName) & (0 ^ combinato" ascii
    $s14 = "letter = (((1 + traditional) * (12 + getElementsByClassName) + (10 ^ ignored)), (((11 + getElementsByClassName) & (0 ^ combinato" ascii
    $s15 = "ive) | (2 | push_native))) | ((140 / reverse) + ((1 * isSimulated) + (116 & setTimeout)))) / ((Math.pow(((15 + manipulationTarge" ascii
    $s16 = "version[dataTypes + srcElements]();" fullword ascii
    $s17 = "version[once + parentWindow]();" fullword ascii
    $s18 = "while (ajaxTransport[settings + sourceIndex + urlAnchor + checked + origType] < (2 * push_native)) {" fullword ascii
    $s19 = "ajaxTransport[root]();" fullword ascii
    $s20 = "getText = \"tp\", curLeft = \"C\", traditional = 14;" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}