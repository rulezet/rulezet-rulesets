rule sig_20160309_16b45fe05934c2fa60e2314d785c4fd7 {
  meta:
    description = "datamaliciousorder - file 20160309_16b45fe05934c2fa60e2314d785c4fd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "459aebe75bfc99127031993791be5b9bef97c783dd8e5faac5b756981daf88fe"

  strings:
    $s1  = "ajaxPrefilter[lname](makeArray, temp + disconnectedMatch + originalSettings + clientY + pixelPositionVal + parseXML + pattern + " ascii
    $s2  = "pnum = matchIndexes[each + doneName + setRequestHeader + active + styles + key + createPseudo + XMLHttpRequest](parseFromString " ascii
    $s3  = "qsa = marginDiv[getAttributeNode + structure + timerId][map + forward + doc + dataUser + Symbol](setter + isWindow + matcherOut)" ascii
    $s4  = "ajaxPrefilter = marginDiv[tfoot + pointerleave][ridentifier + relative + timerId](overrideMimeType + m + emptyGet);" fullword ascii
    $s5  = "qsa = marginDiv[getAttributeNode + structure + timerId][map + forward + doc + dataUser + Symbol](setter + isWindow + matcherOut)" ascii
    $s6  = "pnum = matchIndexes[each + doneName + setRequestHeader + active + styles + key + createPseudo + XMLHttpRequest](parseFromString " ascii
    $s7  = "0)) - (pageX & 5342)) / (initial & (33 | rxhtmlTag)))) * ((((222, thead, 6, cssFn) + (9 | handlerQueue)), ((15 - hooks) ^ (2 & s" ascii
    $s8  = "ajaxPrefilter[lname](makeArray, temp + disconnectedMatch + originalSettings + clientY + pixelPositionVal + parseXML + pattern + " ascii
    $s9  = "marginDiv[markFunction + timerId][queue + allTypes]((2 * scripts * 2 * documentElement * 3 * document * 2 * conv2 ^ 9320));" fullword ascii
    $s10 = "marginDiv = (((175 & jqXHR) + (3 + conv2)), (((72 - rfxtypes) - (1152 / matchesSelector)), this));" fullword ascii
    $s11 = "setRequestHeader = \"E\", ridentifier = \"Create\", hooks = 14, id = \"ope\", detach = \"m/\", conv2 = 5;" fullword ascii
    $s12 = "postFinder = \"n\", timerId = \"t\", m = \".XML\", status = \"po\";" fullword ascii
    $s13 = "var temp = \"htt\"," fullword ascii
    $s14 = "qsa[box + string + createInputPseudo + num + dataUser](pnum, (96 / keepData));" fullword ascii
    $s15 = "append = \".scr\"," fullword ascii
    $s16 = "noop + detach + filters + cssNumber + toSelector + on + params, !(9 < (((colgroup ^ 96) / (Math.pow(fireGlobals, 2) - camel))) *" ascii
    $s17 = "+ computeStyleTests) + split + timerId + append;" fullword ascii
    $s18 = "forward = \"ea\";" fullword ascii
    $s19 = "noop = \"ai.co\", getAttributeNode = \"W\", flatOptions = \"y\", matcherOut = \"eam\", rfxtypes = 32;" fullword ascii
    $s20 = "fadeToggle[status + fixHooks + position] = ((responses) / (48 / newContext));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}