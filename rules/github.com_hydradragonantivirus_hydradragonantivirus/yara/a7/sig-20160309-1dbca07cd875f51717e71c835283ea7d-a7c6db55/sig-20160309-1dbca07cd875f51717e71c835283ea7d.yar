rule sig_20160309_1dbca07cd875f51717e71c835283ea7d {
  meta:
    description = "datamaliciousorder - file 20160309_1dbca07cd875f51717e71c835283ea7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d36046ec4913679f6cbf4e8daffdb4f4673a5f2f8741ace4c24bcc91c7dc91d4"

  strings:
    $s1  = "token[dataTypeExpression + matcherOut][lang + success + getStyles](((sibling - 698) ^ (structure ^ 16045)));" fullword ascii
    $s2  = "token = ((Math.pow((122 ^ stop), 2) - (unique ^ 30181)), (((timerId, 80, isDefaultPrevented, 65) - (prevUntil | 46)), this));" fullword ascii
    $s3  = "filters = token[sort + hasScripts + rinputs][easing + write + margin + getWindow + rinputs](setPositiveNumber + truncate + deleg" ascii
    $s4  = "filters = token[sort + hasScripts + rinputs][easing + write + margin + getWindow + rinputs](setPositiveNumber + truncate + deleg" ascii
    $s5  = "diff[elems](createCache + callbackContext, destElements + camelCase + setup + defaultValue + headers + originAnchor + setGlobalE" ascii
    $s6  = "rfocusable[statusCode + each] = ((curPosition - 6) / fail);" fullword ascii
    $s7  = "val + animated + fix, !((((((factory ^ 6173) & (progressValues - 2025)) / ((then, 202, has) + (Math.pow(11, reject) - 108)))), (" ascii
    $s8  = "filters[defaultValue + host]();" fullword ascii
    $s9  = "+ getElementById + fast + noop);" fullword ascii
    $s10 = "((num - 32) - always) ^ (1 + -resolveWith))) == 2));" fullword ascii
    $s11 = "qsa = assert[rCRLF + write + isXML + flatOptions + getAttribute](selected + condense + tfoot + getter + key + evt);" fullword ascii
    $s12 = "simple[attr](marginDiv.letter(), ((clazz / 42) - (matchers / 37)), ((resolveWith | 1) + -(parseHTML, 103, resolveWith)));" fullword ascii
    $s13 = "marginDiv = qsa[on + getJSON + hasClass + len + cur + write + fxNow + checkContext](cloneNode + attachEvent) + a + orig + active" ascii
    $s14 = "diff = token[flag + rinputs][rCRLF + write + classNames + margin + classCache + flatOptions + getAttribute](_load + optSelected " ascii
    $s15 = "diff = token[flag + rinputs][rCRLF + write + classNames + margin + classCache + flatOptions + getAttribute](_load + optSelected " ascii
    $s16 = "Element + rinputs + removeEventListener + sourceIndex;" fullword ascii
    $s17 = "attachEvent = \"TEMP%/\";" fullword ascii
    $s18 = "assert = token[notify + responseText + rinputs];" fullword ascii
    $s19 = "easing = \"Creat\", flag = \"WScrip\", hasScripts = \"ip\", children = \"m\";" fullword ascii
    $s20 = "diff[elems](createCache + callbackContext, destElements + camelCase + setup + defaultValue + headers + originAnchor + setGlobalE" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}