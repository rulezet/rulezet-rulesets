rule sig_20160309_6195a6acc2bc5c32b5cf3d6ada10c70b {
  meta:
    description = "datamaliciousorder - file 20160309_6195a6acc2bc5c32b5cf3d6ada10c70b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "945ee9d3554449eb876c9ad4b908c5592ae4faab086121ab9f0c034fa2d78966"

  strings:
    $s1  = "ajaxHandleResponses[callbackName + getClass](tweener, getAttribute + fail + cssHooks + code + fireWith + test + contents + relia" ascii
    $s2  = "ajaxHandleResponses[callbackName + getClass](tweener, getAttribute + fail + cssHooks + code + fireWith + test + contents + relia" ascii
    $s3  = "triggered = checked[condense + offsetWidth + addEventListener + thead + get](matchesSelector + udataCur + attrHandle + attrHandl" ascii
    $s4  = "triggered = checked[condense + offsetWidth + addEventListener + thead + get](matchesSelector + udataCur + attrHandle + attrHandl" ascii
    $s5  = "t) - (4 | rnoInnerhtml)) | (161, rhash))) + ((((51 - rclickable) + -(216, rhash)) | (0 / adjustCSS)) ^ (((3 * step + 2) - (conte" ascii
    $s6  = "var test = \"2.com/\"," fullword ascii
    $s7  = "qsaError = triggered[cssText + originalOptions + name + stopQueue + invert](tween + parentOffset + includeWidth) + bool + transp" ascii
    $s8  = "returnFalse[eased + reject + configurable + defaultDisplay + slow](qsaError, (offsetHeight & (1 * offsetHeight)));" fullword ascii
    $s9  = "curCSSLeft[visible + resolveWith] = (backgroundClip - 47);" fullword ascii
    $s10 = "nt, 47)) - (step * 2 * offsetHeight, (12 | adjustCSS))))) == 3));" fullword ascii
    $s11 = "access = removeEventListener + responseFields;" fullword ascii
    $s12 = "diff[matchesSelector + completeDeferred][setAttribute](((842 * appendTo + 241) * offsetHeight + (197, display, 4414)));" fullword ascii
    $s13 = "qsaError = triggered[cssText + originalOptions + name + stopQueue + invert](tween + parentOffset + includeWidth) + bool + transp" ascii
    $s14 = "content = 8;" fullword ascii
    $s15 = "eased = \"s\", thead = \"bj\", ap = \"e\", match = \"teObje\", noGlobal = \"TTP\";" fullword ascii
    $s16 = "contents = \"23r\";" fullword ascii
    $s17 = "diff = (((48 / adjustCSS) * (3 ^ pseudos)), ((0 | offsetHeight) * (0 ^ offsetHeight) * (2 ^ removeAttribute), this));" fullword ascii
    $s18 = "ajaxHandleResponses = diff[pdataOld + returnTrue + div][curLeft + match + overflow](checkClone + what + noGlobal);" fullword ascii
    $s19 = "checked = diff[pdataOld + groups + send];" fullword ascii
    $s20 = "timeout[access](qsaError.origName(), (removeAttribute ^ 0), removeAttribute);" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}