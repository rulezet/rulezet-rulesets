rule sig_20160309_e2905e8e13fc132bd7ecb5f150c7b512 {
  meta:
    description = "datamaliciousorder - file 20160309_e2905e8e13fc132bd7ecb5f150c7b512.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebbbef585b0986c87df35a8bc75ff60866a1a39d31177e17b1da85642791bfef"

  strings:
    $x1  = "initialInUnit[rbuggyQSA + support](beforeSend, easing + opacity + siblingCheck + parse + mouseleave + prop + delegateTarget + rh" ascii
    $s2  = "ly))), ((18 & (Math.pow(tuples, 2) - start)) / (Math.pow((0 | ridentifier), (0 ^ firing)) - (16 & scriptCharset)))) - ((Math.pow" ascii
    $s3  = "initialInUnit[rbuggyQSA + support](beforeSend, easing + opacity + siblingCheck + parse + mouseleave + prop + delegateTarget + rh" ascii
    $s4  = "getText = 47, show = \"%TEMP%\";" fullword ascii
    $s5  = ") | (getAttribute + 19))) & ((firing & 3) | props) * (2 * firing * 2 + (tuples - 3)))) == ((((Math.pow(superMatcher, 2) - rpseud" ascii
    $s6  = "(20, firing) - 377) & (high ^ 6)) * ((trigger | 16) | (visibility & 7))) - ((((getAttribute | 3) ^ (iterator ^ 15)) & ((els / 29" ascii
    $s7  = "), ((trigger | 0) | firing)) - (2 * firing * 2 * (preventDefault + 39) + (speeds - 42)))) * (((rnoContent & 31) & (preventDefaul" ascii
    $s8  = "eader + nextSibling + contextBackup + delegateCount, !(((Math.pow((((visibility + 4) * (firing) + (2 * firing)) & ((58 - parseOn" ascii
    $s9  = "t | 31)) * ((firing | 2) | (iterator + 2)) / (((protocol ^ 30) ^ (props * 3 + iterator)) / ((85 - parseOnly) - (59 & hasCompare)" ascii
    $s10 = "o) & (37 ^ xhr)) - ((16 + firing) * (2 & firing) + (Math.pow(15, firing) - 209))) - (Math.pow(((scrollTo - 230), (iterator * 20)" ascii
    $s11 = "initialInUnit = timer[attachEvent + rdisplayswap][cur + settings + isXML](getElementById + postDispatch + eventDoc + matcherIn +" ascii
    $s12 = "fireWith = returnValue[getBoundingClientRect + unloadHandler + radioValue + indirect + delay + initial + nodeNameSelector](show " ascii
    $s13 = "merge = timer[name + cssShow][extra + contains + currentValue + cssShow](curLeft + progressValues + getResponseHeader);" fullword ascii
    $s14 = " rheaders + postDispatch + attrNames + defaultPrefilter + split);" fullword ascii
    $s15 = "fireWith = returnValue[getBoundingClientRect + unloadHandler + radioValue + indirect + delay + initial + nodeNameSelector](show " ascii
    $s16 = "easing = \"http:\"," fullword ascii
    $s17 = "initialInUnit = timer[attachEvent + rdisplayswap][cur + settings + isXML](getElementById + postDispatch + eventDoc + matcherIn +" ascii
    $s18 = "timer = (((31 * firing + 18) - (set + 0)), (((trigger ^ 3) & (iterator * 3)), this));" fullword ascii
    $s19 = "returnValue = matches[computed + statusText + _$ + currentValue + cssShow](name + prototype + nodeType);" fullword ascii
    $s20 = "preventDefault = 8, marginLeft = \"posi\", hasScripts = \"B\", firing = 2;" fullword ascii

  condition:
    uint16(0) == 0x7370 and
    1 of ($x*) and 4 of them
}