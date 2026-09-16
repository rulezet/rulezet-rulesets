rule sig_20160307_4af2614bcc7baa4ea82c7eacafffafab {
  meta:
    description = "datamaliciousorder - file 20160307_4af2614bcc7baa4ea82c7eacafffafab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d95cb3b6235c445c363cc4f4b6d09c2f4682f4a072c6096d62eae3eb970e685d"

  strings:
    $s1  = "addEventListener = reset[rmultiDash + original][cleanData + target + orig](rfxtypes + left + dirrunsUnique + rcheckableType + re" ascii
    $s2  = "addEventListener = reset[rmultiDash + original][cleanData + target + orig](rfxtypes + left + dirrunsUnique + rcheckableType + re" ascii
    $s3  = "reset[collection + sortStable + identifier][binary + factory]((Math.pow((83 & box), (204, attributes)) - 73 * ajax * 31));" fullword ascii
    $s4  = "rdashAlpha = transports[onload + bulk + textContent + responseHeaders + dataShow](soFar + resolveWith + parentWindow);" fullword ascii
    $s5  = "addEventListener[container + ajaxTransport](round + unshift + hasOwn, width + letterSpacing + overrideMimeType + dataTypeExpress" ascii
    $s6  = "addEventListener[container + ajaxTransport](round + unshift + hasOwn, width + letterSpacing + overrideMimeType + dataTypeExpress" ascii
    $s7  = "reset[soFar + _][defaultDisplay + removeProp + factory](((dataAndEvents ^ 27999) - (addCombinator | 2972)));" fullword ascii
    $s8  = "reset = (((Math.pow(215, attributes) - 45858) & gotoEnd * 19), ((ajax ^ 6), this));" fullword ascii
    $s9  = "target = \"ateO\";" fullword ascii
    $s10 = "ajaxPrefilter = reset[collection + valueParts + callback + returnValue][valHooks + document + manipulationTarget + _](rheader + " ascii
    $s11 = "ajaxPrefilter = reset[collection + valueParts + callback + returnValue][valHooks + document + manipulationTarget + _](rheader + " ascii
    $s12 = "options = \"po\", addCombinator = 4272, settings = \"f3\", dataAndEvents = 15115, ajaxTransport = \"en\", tick = \"Run\";" fullword ascii
    $s13 = "ion + notify + rsibling + noGlobal + cssText + input + defineProperty + settings, !((((((rsubmittable / 44) - origType * 5) - ((" ascii
    $s14 = "stopOnFalse[pseudo + ajaxSettings] = (ajax * 2 - origType);" fullword ascii
    $s15 = "maxWidth[obj](list.isXMLDoc(), ((1 + -lock) | (0 / ajax)), (0 & (lock & 1)));" fullword ascii
    $s16 = "rclass | 9) + (show / 47))) | ((lock ^ 4) | (Math.pow(origType, 2) - curTop)))) == 7));" fullword ascii
    $s17 = "transports = reset[rmultiDash + createTween + isBorderBox];" fullword ascii
    $s18 = "ajaxPrefilter[script]();" fullword ascii
    $s19 = "superMatcher = \"new\", augmentWidthOrHeight = \"ri\", sortStable = \"Scri\", script = \"open\";" fullword ascii
    $s20 = "ajaxPrefilter[matchExpr + srcElements](list, (2 + replaceChild));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}