rule sig_20160309_eccc083354d190a4b73f222f34587bdc {
  meta:
    description = "datamaliciousorder - file 20160309_eccc083354d190a4b73f222f34587bdc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db1fcf73f9ab4f172386ace5e6e1d3f5f90512fe33747a9300e1861373269770"

  strings:
    $s1  = "indirect = temp[disable + curOffset + isSuccess + margin + charset + deepDataAndEvents + flag](off + fx + fast) + actualDisplay " ascii
    $s2  = "((stopped) & (3 * onerror)))), ((((Math.pow(5, onerror) - 18) - (getAttribute / 26)) & ((removeChild + 0) + pixelPositionVal)) |" ascii
    $s3  = "temp = currentValue[jQuery + grep + expand + keyCode + destElements](_$ + username + responseContainer + rmultiDash + structure)" ascii
    $s4  = "temp = currentValue[jQuery + grep + expand + keyCode + destElements](_$ + username + responseContainer + rmultiDash + structure)" ascii
    $s5  = "rhtml[div1](location + pointerenter, window + what + selected + tfoot + preferredDoc + startTime + reliableMarginLeftVal + Symbo" ascii
    $s6  = "percent[_$ + keys][wait + Deferred](((Math.pow(curCSSLeft, 2) - markFunction), (14480 | rjsonp)));" fullword ascii
    $s7  = "options[emptyGet + curValue + iframe](indirect, (pnum / 10));" fullword ascii
    $s8  = "charCode = rhtml[val + rkeyEvent + time + sortOrder];" fullword ascii
    $s9  = " (((0 | onerror) & (0 ^ amd))))) - ((((56, dataShow, 219, progress) | (40 & appendTo)) - (3 * (split & 6) + (pixelPositionVal | " ascii
    $s10 = "indirect = temp[disable + curOffset + isSuccess + margin + charset + deepDataAndEvents + flag](off + fx + fast) + actualDisplay " ascii
    $s11 = "percent = (((6192 | urlAnchor) / (36 | isReady)), (((13 + rreturn) / 17 * onerror), this));" fullword ascii
    $s12 = "options[defaultExtra + operator]();" fullword ascii
    $s13 = "1))) ^ (((cos | 0), (pushStack | 202), dataType, (96 + getWidthOrHeight)) & ((5 ^ progress) * 2 + amd * 5))))));" fullword ascii
    $s14 = "getAttribute = 182, operator = \"pen\", startTime = \"h\", risSimple = \"Run\", duplicates = \"i6u5y\";" fullword ascii
    $s15 = "size[rpseudo + code] = ((removeChild * 0) & (view - 25));" fullword ascii
    $s16 = "trigger[offsetHeight](indirect.rmsPrefix(), (1 + -removeChild), ((44 - load) & (1 & removeChild)));" fullword ascii
    $s17 = "selection[doc] = ((firstDataType - 8) / (progress & 46));" fullword ascii
    $s18 = "trigger = temp;" fullword ascii
    $s19 = "options = percent[clientLeft + responseContainer][unwrap + progressContexts + subtract + rdisplayswap](sort + a + handleObj + ma" ascii
    $s20 = "rhtml[flag + clearTimeout]();" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}