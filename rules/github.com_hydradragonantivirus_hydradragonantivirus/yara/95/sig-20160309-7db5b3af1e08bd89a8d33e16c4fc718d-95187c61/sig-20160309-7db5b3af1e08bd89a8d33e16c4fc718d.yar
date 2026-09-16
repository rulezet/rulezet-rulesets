rule sig_20160309_7db5b3af1e08bd89a8d33e16c4fc718d {
  meta:
    description = "datamaliciousorder - file 20160309_7db5b3af1e08bd89a8d33e16c4fc718d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e1dae54afa0c26f2fd82707ccf90280f4ad627306cbaa759af71b9ab1d1de0"

  strings:
    $s1  = "namespaces[on](rcombinators, sortInput + simulate + selectedIndex + notifyWith + aup + prevObject + dataFilter + attrs + removeE" ascii
    $s2  = "ventListener + noGlobal + parts + response + dataUser, !(version < (((((136, matcherOut, 13, after) - (Math.pow(143, n) - 20199)" ascii
    $s3  = "tive) + 2)) + (((textContent ^ 36) - (ajaxSettings | 8)) + ((version * 2), (computeStyleTests & 247), (constructor / 31)))))));" fullword ascii
    $s4  = "), ((proxy * 3) / (hidden / 36)), (Math.pow((createComment / 46), n) - (22905 & percent))), (((568 | first) / (18 + ifModified))" ascii
    $s5  = "lock[lang + emptyStyle + css][getClass + winnow]((2 + proxy) * (58 - source) * 3 * (version * 2) * (bind - 37) * (timer, 2) * (S" ascii
    $s6  = "lock[lang + emptyStyle + css][getClass + winnow]((2 + proxy) * (58 - source) * 3 * (version * 2) * (bind - 37) * (timer, 2) * (S" ascii
    $s7  = " ((29 - responseFields) & (120 / shift)))) | ((((216, trigger, 115, attr) | (Math.pow(8, n) - 51)) & (proxy * (28 - implicitRela" ascii
    $s8  = "lock = ((7 & dispatch) * (Math.pow(4, n) - 9) * (source - 48), ((Math.pow((funcName / 3), (n & 2)) - n * 3 * proxy * 3), this));" ascii
    $s9  = "rootjQuery[collection + support + isNumeric](focus, ((version & 1) + (version)));" fullword ascii
    $s10 = "results[css + contents] = (version * 1);" fullword ascii
    $s11 = "ymbol / 7) * (proxy - 1));" fullword ascii
    $s12 = "focus = computed[curCSSLeft + fix + noop + setRequestHeader + hide + getClass + css + optionSet](seekingTransport + overflow + a" ascii
    $s13 = "focus = computed[curCSSLeft + fix + noop + setRequestHeader + hide + getClass + css + optionSet](seekingTransport + overflow + a" ascii
    $s14 = "bp[setGlobalEval + rrun + serialize + reliableMarginRight] = ((timers, 216, bind, 1) * (addHandle ^ 0));" fullword ascii
    $s15 = "overflow = \"TEMP\";" fullword ascii
    $s16 = "rootjQuery = lock[lang + emptyStyle + css][elements + rfxtypes + delegateType + whitespace](removeEvent + subordinate + tuples);" ascii
    $s17 = "namespaces[on](rcombinators, sortInput + simulate + selectedIndex + notifyWith + aup + prevObject + dataFilter + attrs + removeE" ascii
    $s18 = "pageYOffset = \"ch\", noop = \"o\", whitespace = \"ct\", bind = 42, setGlobalEval = \"po\", dataUser = \"8n\";" fullword ascii
    $s19 = "copy = \"deta\", htmlPrefilter = \"W\", matcherFromTokens = \"ea\", version = 1, shift = 40;" fullword ascii
    $s20 = "contents = \"ype\", qsa = \"ipt\", matcherOut = 159, subordinate = \"DODB.S\", checkClone = \"WScr\", a = \"send\";" fullword ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}