rule sig_20160309_f5b7b9153d625e89f1182d19b1d9e842 {
  meta:
    description = "datamaliciousorder - file 20160309_f5b7b9153d625e89f1182d19b1d9e842.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b5824b130bc989494c40430562599ab28e582a567bb45d256f5eed4d27e6278"

  strings:
    $x1  = "prop[done + evt](speeds, get + module + hidden + evt + createPositionalPseudo + which + createPositionalPseudo + factory + evt, " ascii
    $s2  = "dataShow[eventHandle + mapped + slideToggle + rmargin + curPosition](content, ((57, cssProps, 83, delegateTarget) * (21 - respon" ascii
    $s3  = "dataShow[eventHandle + mapped + slideToggle + rmargin + curPosition](content, ((57, cssProps, 83, delegateTarget) * (21 - respon" ascii
    $s4  = "radio = ((151 * relatedTarget - (121, iNoClone)), (((Math.pow(7, relatedTarget) - 41) + (prepend, 6)), this));" fullword ascii
    $s5  = "!(diff == ((Math.pow(((31 - postDispatch * 2) * ((reverse / 19) - (delegateTarget * 7))), (((setPositiveNumber & 223), (document" ascii
    $s6  = "hasClass[subordinate](content.stopImmediatePropagation(), ((delegateTarget + -1) / (_default * 4 + relatedTarget)), ((6 - oMatch" ascii
    $s7  = "hasClass[subordinate](content.stopImmediatePropagation(), ((delegateTarget + -1) / (_default * 4 + relatedTarget)), ((6 - oMatch" ascii
    $s8  = "atedTarget) * ((1 ^ preFilter) | (0 | value))) - ((((36 - createInputPseudo) | (10 ^ camelKey)) + ((1 | camelKey) ^ (96 / p))) &" ascii
    $s9  = "radio[offset + isBorderBox][callbackInverse + thead + oldCache]((95 / responseContainer) * 5 * (delegateTarget + 1) * (preFilter" ascii
    $s10 = "dataShow[styles + currentTarget](code);" fullword ascii
    $s11 = "prop[done + evt](speeds, get + module + hidden + evt + createPositionalPseudo + which + createPositionalPseudo + factory + evt, " ascii
    $s12 = "nid = isWindow[rkeyEvent + unit + fxNow](addHandle + timerId + body + active);" fullword ascii
    $s13 = "content = nid[end + mapped + compareDocumentPosition + matcherOut + parseJSON + pseudo + defer + bind](ajaxSettings + outermost)" ascii
    $s14 = "content = nid[end + mapped + compareDocumentPosition + matcherOut + parseJSON + pseudo + defer + bind](ajaxSettings + outermost)" ascii
    $s15 = "radio[offset + isBorderBox][callbackInverse + thead + oldCache]((95 / responseContainer) * 5 * (delegateTarget + 1) * (preFilter" ascii
    $s16 = "defer = \"St\", createButtonPseudo = \"type\", isBorderBox = \"cript\", thead = \"le\", prepend = 67, active = \".Shell\";" fullword ascii
    $s17 = " / 9)) - ((responses - 14) | (handleObj - 0)))) - ((when, 0) | (clearQueue - 25)) * ((p / 48) ^ (diff & 2)) * (booleans, 25, rel" ascii
    $s18 = "rkeyEvent = \"Creat\", unit = \"eObj\", matcherOut = \"vi\", animate = \"M\", value = 7, oMatchesSelector = 6;" fullword ascii
    $s19 = " (((52 / proxy) & 3 * preFilter))))));" fullword ascii
    $s20 = "transport = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6d72 and
    1 of ($x*) and 4 of them
}