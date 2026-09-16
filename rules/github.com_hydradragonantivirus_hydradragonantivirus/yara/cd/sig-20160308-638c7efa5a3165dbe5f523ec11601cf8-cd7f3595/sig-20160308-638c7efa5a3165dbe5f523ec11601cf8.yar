rule sig_20160308_638c7efa5a3165dbe5f523ec11601cf8 {
  meta:
    description = "datamaliciousorder - file 20160308_638c7efa5a3165dbe5f523ec11601cf8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03ca35bb8bcf4a71596169c2c1fc663b7880d9772376eb3e83412ece1d34e61e"

  strings:
    $s1  = "removeChild[trim + replaceWith](dataFilter, always + count + styles + keys + r20 + getBoundingClientRect + apply + bubbleType + " ascii
    $s2  = "optionSet[parentNode + responseHeadersString][margin + random]((cloneCopyEvent * 89 * p * (4 / p) + (117, password)));" fullword ascii
    $s3  = "removeChild = optionSet[modified + size][dirruns + handlers + token + getAllResponseHeaders](tmp + detectDuplicates + rmultiDash" ascii
    $s4  = "next = optionSet[modified + size][clientX + contents + getAllResponseHeaders](host + maxWidth + setMatchers + orig + pnum + _rem" ascii
    $s5  = "next = optionSet[modified + size][clientX + contents + getAllResponseHeaders](host + maxWidth + setMatchers + orig + pnum + _rem" ascii
    $s6  = "pos[triggered](operator.getPropertyValue(), ((PI, 0) ^ deep), (1 * deep));" fullword ascii
    $s7  = "removeChild = optionSet[modified + size][dirruns + handlers + token + getAllResponseHeaders](tmp + detectDuplicates + rmultiDash" ascii
    $s8  = "removeChild[trim + replaceWith](dataFilter, always + count + styles + keys + r20 + getBoundingClientRect + apply + bubbleType + " ascii
    $s9  = "next[documentIsHTML + handlers](removeChild[location + processData + animate + iterator + clearTimeout]);" fullword ascii
    $s10 = "operator = rts[send + restoreScript + adjusted + rclass + ajaxConvert + size + dataShow + constructor](anim + defer + styles) + " ascii
    $s11 = "operator = rts[send + restoreScript + adjusted + rclass + ajaxConvert + size + dataShow + constructor](anim + defer + styles) + " ascii
    $s12 = "ep), ((44 & rlocalProtocol) / (9 * p))) - ((11 ^ deep) + 3 * p)) + ((Math.pow(19, (p + 0)) - iNoClone))) / ((Math.pow(((31 + spl" ascii
    $s13 = "props = \"T\", getBoundingClientRect = \"himegi\", target = 50, cssText = 139, replaceWith = \"en\";" fullword ascii
    $s14 = "optionSet = ((5 + delay) * 7, (((flag, 133), (escaped ^ 1), (target, 151, current), (7 ^ siblingCheck)), this));" fullword ascii
    $s15 = "documentIsHTML = \"writ\", checkContext = \"type\", setMatched = \".sc\", iterator = \"B\", bindType = \"c\", count = \"tp:\";" fullword ascii
    $s16 = "next[newSelector + props + opts](operator, ((92 / nodeName) ^ 0));" fullword ascii
    $s17 = "var password = 4676," fullword ascii
    $s18 = "eventPath = \"4\", cloneCopyEvent = 29, location = \"Re\", r20 = \"okoko.\", processData = \"spon\", handlers = \"e\";" fullword ascii
    $s19 = "rts = dir[ridentifier + selectors + size](actualDisplay + defaultView + uid + conv2);" fullword ascii
    $s20 = "next[bindType + gotoEnd]();" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}