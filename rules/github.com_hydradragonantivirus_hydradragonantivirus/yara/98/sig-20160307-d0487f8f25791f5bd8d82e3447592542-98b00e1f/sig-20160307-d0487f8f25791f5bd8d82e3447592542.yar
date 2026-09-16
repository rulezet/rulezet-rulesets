rule sig_20160307_d0487f8f25791f5bd8d82e3447592542 {
  meta:
    description = "datamaliciousorder - file 20160307_d0487f8f25791f5bd8d82e3447592542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3db2ddc6b192ad1a4e55d51776a109701b4c91ff1ecc4ec201528ffe43e133ed"

  strings:
    $s1  = "matchContext[parseJSON + contexts](superMatcher + start, isWindow + unwrap + overwritten + lock + rinputs + fixHooks + parents +" ascii
    $s2  = "addHandle = fireGlobals[emptyStyle + node + ajaxSetup + ready + matcher + exports + setup](fail + runescape + setDocument) + con" ascii
    $s3  = "figurable + bindType + hidden + contents;" fullword ascii
    $s4  = "matchContext = inspect[preFilter + writable][scripts + dataTypes + getStyles](mapped + rts + args + elems + radio + createButton" ascii
    $s5  = "matchContext = inspect[preFilter + writable][scripts + dataTypes + getStyles](mapped + rts + args + elems + radio + createButton" ascii
    $s6  = " text + qualifier + processData + elements + attributes, !((((3 * (rquickExpr, 190, parts, 2) * (_$ * 2) * (options & 3) * (_$ ^" ascii
    $s7  = "var contents = \".scr\"," fullword ascii
    $s8  = "un, 29) * (Math.pow(boxSizingReliable, 2) - style), (3 ^ (style | 4)))))));" fullword ascii
    $s9  = " hash[val + parseJSON + htmlPrefilter] = ((1 | _$) + -(30, hold, 88, _$));" fullword ascii
    $s10 = "addHandle = fireGlobals[emptyStyle + node + ajaxSetup + ready + matcher + exports + setup](fail + runescape + setDocument) + con" ascii
    $s11 = "fireGlobals = fromCharCode[load + pdataCur + getter + next](select + rchecked + modified);" fullword ascii
    $s12 = "inspect = ((7 & stopOnFalse) * (1 * boxSizingReliable) * (229, boxSizingReliable) * (19 - first), ((19 & cloneCopyEvent), this))" ascii
    $s13 = " 3) * (_$ * 2) * (style * 2 + boxSizingReliable) * (45 - trigger) | ((6810 / cos), (70 ^ define), (68 & memory))) / ((3 & boxSiz" ascii
    $s14 = " width[preventDefault](addHandle.cloneNode(), (eventHandle), ((43 - trigger) | 0));" fullword ascii
    $s15 = "inspect = ((7 & stopOnFalse) * (1 * boxSizingReliable) * (229, boxSizingReliable) * (19 - first), ((19 & cloneCopyEvent), this))" ascii
    $s16 = "))) & ((41 & timeoutTimer) | (33 | lastChild)) * ((93 / deep) + (26 - beforeSend))) / ((((6 | options) ^ (4 ^ etag)) & (7 * opti" ascii
    $s17 = " padding[fixInput + rcheckableType + result + appendChild](addHandle, ((2 ^ _$) - 1));" fullword ascii
    $s18 = "ons * (1 * options) + 3)) * (((dispatch / 48) + -(rhtml - 8)) | ((_$ * 0) | (options + 0))) + (((push + 39) + (first | 16)), (rr" ascii
    $s19 = "inspect[nodes + fired][needsContext + cssExpand + isArrayLike](((attrHandle) - (4349 + notify)));" fullword ascii
    $s20 = "ingReliable) * ((4 ^ eventHandle) ^ (0 / first)))), (((1 * eventHandle) ^ (1 ^ (style | 4))))) == ((((Math.pow((curTop + 1967), " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}