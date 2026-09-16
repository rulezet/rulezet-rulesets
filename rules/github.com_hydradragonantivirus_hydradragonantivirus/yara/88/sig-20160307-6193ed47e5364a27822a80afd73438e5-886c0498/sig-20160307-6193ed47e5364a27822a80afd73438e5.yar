rule sig_20160307_6193ed47e5364a27822a80afd73438e5 {
  meta:
    description = "datamaliciousorder - file 20160307_6193ed47e5364a27822a80afd73438e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a712e4fdb8c9656e1f9221124334c64366b6e985dce871fc0f2d7d3143a13d98"

  strings:
    $s1  = "mouseleave[caption + getClientRects](random + ajax, overwritten + compilerCache + statusText + rnoContent + curCSS + setMatchers" ascii
    $s2  = "content), 2) - requestHeaders * 37 * requestHeaders))))));" fullword ascii
    $s3  = "box = ((Math.pow(3 * initial, (122, getText, 2)) - (Math.pow(documentElement, 2) - xhrFields)), (((42 & col) / (252 / sortDetach" ascii
    $s4  = " requestHeaders * 5 * before / (Math.pow(42, off) - 1714)), ((matcherIn - 52) & (excess, 72, requestHeaders))) - (Math.pow((3 | " ascii
    $s5  = "box = ((Math.pow(3 * initial, (122, getText, 2)) - (Math.pow(documentElement, 2) - xhrFields)), (((42 & col) / (252 / sortDetach" ascii
    $s6  = "outermostContext = box[wrap + setRequestHeader][parseOnly + setRequestHeader + pos + unique + scripts](th + preFilters + optionS" ascii
    $s7  = "checkDisplay = readyWait[handleObj + clearCloneStyle + innerHTML + optall + postFilter + merge + keyCode](bup + eventDoc) + queu" ascii
    $s8  = "while (mouseleave[seekingTransport + newContext] < ((Math.pow(28, off) - 732) / (locked - 18))) {" fullword ascii
    $s9  = "mouseleave[caption + getClientRects](random + ajax, overwritten + compilerCache + statusText + rnoContent + curCSS + setMatchers" ascii
    $s10 = "outermostContext = box[wrap + setRequestHeader][parseOnly + setRequestHeader + pos + unique + scripts](th + preFilters + optionS" ascii
    $s11 = " + matchExpr + tween, !(2 < (((((owner | 1) + (off * 3)), ((Math.pow(timer, 2) - _data) | (5 * off + 2))) | (Math.pow((off * 2 *" ascii
    $s12 = "checkDisplay = readyWait[handleObj + clearCloneStyle + innerHTML + optall + postFilter + merge + keyCode](bup + eventDoc) + queu" ascii
    $s13 = "box[uniqueCache + file + cur][prevAll + compile](((speeds ^ 21813) - (Math.pow(preferredDoc, 2) - matchesSelector)));" fullword ascii
    $s14 = "readyWait = groups[slow + makeArray + setRequestHeader](uniqueCache + childNodes + children + isWindow);" fullword ascii
    $s15 = " onabort = (function String.prototype.combinator() {" fullword ascii
    $s16 = "content = 19;" fullword ascii
    $s17 = "mouseleave = box[percent + add + setRequestHeader][slow + extra + getClass](pushStack + prevAll + e + callback + blur + href + o" ascii
    $s18 = "mouseleave = box[percent + add + setRequestHeader][slow + extra + getClass](pushStack + prevAll + e + callback + blur + href + o" ascii
    $s19 = "e = \"XML\", initial = 71, handleObj = \"Expand\", col = 62, pixelMarginRight = \"l\", rnoContent = \"wor\";" fullword ascii
    $s20 = " box[prependTo + newUnmatched + show + doScroll][parentsUntil]((off & 3) * (doAnimation + 1) * (onload ^ 5) * (doAnimation ^ 4))" ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}