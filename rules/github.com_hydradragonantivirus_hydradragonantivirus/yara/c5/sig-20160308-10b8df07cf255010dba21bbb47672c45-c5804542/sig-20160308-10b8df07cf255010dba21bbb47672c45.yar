rule sig_20160308_10b8df07cf255010dba21bbb47672c45 {
  meta:
    description = "datamaliciousorder - file 20160308_10b8df07cf255010dba21bbb47672c45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b16078764fe2390049c6921983d82e6c4ee78c67a918559a511f593d294de5ec"

  strings:
    $s1  = "rcomma = timeoutTimer[fns + completed + valHooks][support + src + valHooks](showHide + contentType + returnFalse + rheader);" fullword ascii
    $s2  = "ath.pow(54, rwhitespace) - 2846)), (Math.pow((sortOrder + 1), (rwhitespace ^ 0)) - (contents & 14335)), ((sortInput - 106)), (el" ascii
    $s3  = "timeoutTimer = (((408 / contentDocument) | (100 & delegateType)), (((8 - rwhitespace) * 3 + key), this));" fullword ascii
    $s4  = "timeoutTimer[fns + pos + fired + valHooks][currentTarget + styles](((247 | xhrSuccessStatus) - 147));" fullword ascii
    $s5  = "wrap[namespaces](strAbort, genFx + dataPriv + dataFilter + b + has + reverse + cached + overflowY + notifyWith, !(8 < ((((Math.p" ascii
    $s6  = "keys[_$ + content] = ((rwhitespace | 22), (key + -1));" fullword ascii
    $s7  = "winnow[scripts](isImmediatePropagationStopped.replaceWith(), ((0 / rwhitespace) ^ (21 - createHTMLDocument)), (168, sel, 0));" fullword ascii
    $s8  = "currentTarget = \"Sle\", parse = 2247, has = \"6\", xhrSupported = 1710, val = 47;" fullword ascii
    $s9  = "isImmediatePropagationStopped = boxSizingReliableVal[arg + createElement + Deferred + _ + parseFromString + preFilters + transpo" ascii
    $s10 = "wrap = timeoutTimer[pushStack + valHooks][support + src + valHooks](traditional + optDisabled + msMatchesSelector + getElementsB" ascii
    $s11 = "rts + overflow + backgroundClip + updateFunc](keyCode + seed + isDefaultPrevented) + flatOptions + rneedsContext + getWidthOrHei" ascii
    $s12 = "wrap = timeoutTimer[pushStack + valHooks][support + src + valHooks](traditional + optDisabled + msMatchesSelector + getElementsB" ascii
    $s13 = "ow((modified | 34), (index, 2)) - (xhrSupported / 1)) & ((sortDetached * 2 + hold) / (115 / elemdisplay))) - (((93 & write) | (M" ascii
    $s14 = "while(wrap[binary + checkClone + next] < (41 - compiled) * (0 | rwhitespace)) {" fullword ascii
    $s15 = "rcomma[off + serializeArray + valHooks + actualDisplay](wrap[needsContext + fail + overflowX]);" fullword ascii
    $s16 = "rcomma[scrollTop + finish + context + actualDisplay](isImmediatePropagationStopped, (rwhitespace));" fullword ascii
    $s17 = "msMatchesSelector = \"HTT\", binary = \"re\", support = \"Creat\";" fullword ascii
    $s18 = "content = \"on\", serializeArray = \"ri\", overflowX = \"y\";" fullword ascii
    $s19 = "contents = 12283;" fullword ascii
    $s20 = "timeoutTimer[fns + sort + callbackName][filter + origType + Deferred](((parse - 191) * (elemdisplay + 2) + (linear / 42)));" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}