rule sig_20160309_9f94c52523753e833bc0135e7f11b5c4 {
  meta:
    description = "datamaliciousorder - file 20160309_9f94c52523753e833bc0135e7f11b5c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c595e22a085477a223ff8f71356d745cdd7181176bc7a9d9c2f49f8b53ac3897"

  strings:
    $s1  = "fired = (((46, etag, 104, clearTimeout), (98 - get)), (((1 * traditional) & (150, tmp, 201, setAttribute)), this));" fullword ascii
    $s2  = "name = l[complete + parents + second + isReady + cssHooks + inspected + ajaxSettings](addClass + pdataCur) + reset + whitespace " ascii
    $s3  = "l = isPropagationStopped[version + input + originalProperties + getAll + rnative](actualDisplay + needsContext + parseXML + disp" ascii
    $s4  = "l = isPropagationStopped[version + input + originalProperties + getAll + rnative](actualDisplay + needsContext + parseXML + disp" ascii
    $s5  = "processData = \"y\", parse = \"saveT\", rnative = \"t\";" fullword ascii
    $s6  = "fired[defaultValue + _removeData + rnative][finalValue](((30219 & guaranteedUnique) - (8498 | dirrunsUnique)));" fullword ascii
    $s7  = " + returned, !(((((20 / offsetParent) | 0) * ((holdReady | 34), (msg, 252), (propName | 2)) | (((propName ^ 1) & (cleanData, 53," ascii
    $s8  = "response[readyState](name.acceptData(), ((0 & propName)), ((1 * propName) ^ (1 * propName)));" fullword ascii
    $s9  = "tfoot[filter + isReady]();" fullword ascii
    $s10 = "addClass = \"%TEMP%\";" fullword ascii
    $s11 = "name = l[complete + parents + second + isReady + cssHooks + inspected + ajaxSettings](addClass + pdataCur) + reset + whitespace " ascii
    $s12 = "version = \"Create\", pushStack = \"nd\", holdReady = 1;" fullword ascii
    $s13 = "setup[setRequestHeader]();" fullword ascii
    $s14 = "pseudo = fadeOut[matchedCount + ajaxConvert + _evalUrl];" fullword ascii
    $s15 = "fadeOut[buildParams + setDocument](gotoEnd, close + buildFragment + rneedsContext + tbody + uniqueSort + notify + rtypenamespace" ascii
    $s16 = "isPropagationStopped = fired[defaultValue + _removeData + rnative];" fullword ascii
    $s17 = "tfoot[parse + assert](name, (1 * traditional));" fullword ascii
    $s18 = "fadeOut[buildParams + setDocument](gotoEnd, close + buildFragment + rneedsContext + tbody + uniqueSort + notify + rtypenamespace" ascii
    $s19 = "button = \"TT\", r20 = \"ty\", reset = \"elemd\", tmp = 31;" fullword ascii
    $s20 = "tfoot = fired[defaultValue + callbackExpect][version + removeChild + visible](off + display + scale + updateFunc);" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}