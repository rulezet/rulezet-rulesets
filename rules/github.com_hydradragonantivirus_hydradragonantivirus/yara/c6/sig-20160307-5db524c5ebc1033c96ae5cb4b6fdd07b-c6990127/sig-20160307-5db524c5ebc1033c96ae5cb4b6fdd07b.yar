rule sig_20160307_5db524c5ebc1033c96ae5cb4b6fdd07b {
  meta:
    description = "datamaliciousorder - file 20160307_5db524c5ebc1033c96ae5cb4b6fdd07b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8996d173bf165e247f54cb7268debc4e981a6b41ce0c7ed03955a2638243c55a"

  strings:
    $s1  = " + getById + hasData + progressValues + th + acceptData, !(((((adown & 47) - (Math.pow(XMLHttpRequest, 2) - dataUser)) ^ ((27 - " ascii
    $s2  = "cache = tokens[ready + rdisplayswap][result + handlerQueue + stopQueue + rdisplayswap + implicitRelative + constructor + rdispla" ascii
    $s3  = "cache[fxNow + obj](checkClone, active + ofType + access + defineProperty + detectDuplicates + boxSizingReliable + documentIsHTML" ascii
    $s4  = "dataAttr) / (4, subtract))) ^ ((Math.pow(((235 / prefix) & (7 + headers)), ((2 | headers) & (3 ^ headers))) - ((87 ^ chainable) " ascii
    $s5  = "event[teardown + i + binary](unqueued, ((13 - split) + (0 | headers)));" fullword ascii
    $s6  = "tokens = ((10 / tbody) * 19 * (selector - 48), (((adown - 28) ^ (rneedsContext, 171, contents, 28)), this));" fullword ascii
    $s7  = "event = tokens[holdReady + isBorderBox][result + fadeOut + converters + completeDeferred](clearInterval + isPlainObject + parent" ascii
    $s8  = "event = tokens[holdReady + isBorderBox][result + fadeOut + converters + completeDeferred](clearInterval + isPlainObject + parent" ascii
    $s9  = "unqueued = cssText[suffix + close + fadeIn + computed + deep + keepData + detach + a](rootjQuery + delegate + rnamespace) + els " ascii
    $s10 = "unqueued = cssText[suffix + close + fadeIn + computed + deep + keepData + detach + a](rootjQuery + delegate + rnamespace) + els " ascii
    $s11 = "noop[emptyStyle + els] = (0 | headers);" fullword ascii
    $s12 = "event[pseudos + getJSON]();" fullword ascii
    $s13 = "filter = tokens[sortInput + xhr];" fullword ascii
    $s14 = "detach = \"trin\", realStringObj = 42, obj = \"n\", disable = \"wri\", beforeunload = \".scr\", value = \"rip\";" fullword ascii
    $s15 = "documentIsHTML = \"er\", delegate = \"TEMP\", deep = \"ronm\";" fullword ascii
    $s16 = "tokens[errorCallback + value + rdisplayswap][newSelector + handlerQueue + handlerQueue + caption]((duration * 5 * firingIndex * " ascii
    $s17 = "tokens[errorCallback + value + rdisplayswap][newSelector + handlerQueue + handlerQueue + caption]((duration * 5 * firingIndex * " ascii
    $s18 = "compareDocumentPosition = \"MSXML2\", prefix = 47, defineProperty = \"tudi\", dataUser = 589;" fullword ascii
    $s19 = "constructor = \"jec\", div = \"se\", ready = \"WScrip\", completeDeferred = \"ect\";" fullword ascii
    $s20 = "cache = tokens[ready + rdisplayswap][result + handlerQueue + stopQueue + rdisplayswap + implicitRelative + constructor + rdispla" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}