rule sig_20160309_48e454d607c8ebb2225c9bfdcbfa3f8f {
  meta:
    description = "datamaliciousorder - file 20160309_48e454d607c8ebb2225c9bfdcbfa3f8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "921480452ede39141e8d6ac1cecdd5d41f28874bc0afa3c7e5966498044b31e3"

  strings:
    $s1  = ")) + ((isLocal & 213), (readyState + 0)))) ^ ((slideToggle * 2, (visibility | 10), (oldCallbacks - 86), (textContent & 7)) + ((c" ascii
    $s2  = "rescape[sourceIndex](rreturn, box + selectedIndex + forward + constructor + parseOnly + oMatchesSelector + parse + Symbol + rche" ascii
    $s3  = "truncate = t[scripts + wrapAll][overflowY + linear + etag + to](seekingTransport + remaining + head + left + eventPath);" fullword ascii
    $s4  = "t = ((29 * textContent / 1), (((reject * 3 + textContent) - (70 - checked)), this));" fullword ascii
    $s5  = "truncate[allTypes + inspectPrefiltersOrTransports](hasContent);" fullword ascii
    $s6  = "t[scripts + restoreScript + cacheLength][classes + expand + restoreScript]((5 | scale) * (1 * _evalUrl) * (46 - maxWidth) * (27 " ascii
    $s7  = "t[scripts + restoreScript + cacheLength][classes + expand + restoreScript]((5 | scale) * (1 * _evalUrl) * (46 - maxWidth) * (27 " ascii
    $s8  = ") + dirrunsUnique + keys + clearCloneStyle + unloadHandler + delay;" fullword ascii
    $s9  = "excess[valueIsBorderBox](beforeSend.querySelectorAll(), ((1 * fadeTo)), ((6 + getWidthOrHeight), (1736 / pattern), (1 + -scale))" ascii
    $s10 = "excess[valueIsBorderBox](beforeSend.querySelectorAll(), ((1 * fadeTo)), ((6 + getWidthOrHeight), (1736 / pattern), (1 + -scale))" ascii
    $s11 = "hasContent = rescape[createComment + ownerDocument + handle];" fullword ascii
    $s12 = "truncate[getAll + prefilterOrFactory](beforeSend, ((0 | fadeTo) ^ (184, _evalUrl)));" fullword ascii
    $s13 = "delay = \".scr\"," fullword ascii
    $s14 = "- _jQuery) * (1 ^ readyState) * (99 / hidden) * (220 / maxWidth) * (95 / reject));" fullword ascii
    $s15 = "nextAll = \"TEMP%\";" fullword ascii
    $s16 = "beforeSend = func[newCache + div + fromCharCode + size + mapped + removeAttribute + cos + disable](insertBefore + nextAll + dest" ascii
    $s17 = "jQuery[restoreScript + value + optgroup] = (scale * (0 ^ fadeTo));" fullword ascii
    $s18 = "content = \"ipt\";" fullword ascii
    $s19 = "forward = \"i\";" fullword ascii
    $s20 = "head = \"B.S\";" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}