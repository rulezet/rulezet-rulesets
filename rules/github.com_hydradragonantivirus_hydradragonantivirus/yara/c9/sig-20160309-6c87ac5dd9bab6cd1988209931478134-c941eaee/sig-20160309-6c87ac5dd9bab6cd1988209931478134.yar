rule sig_20160309_6c87ac5dd9bab6cd1988209931478134 {
  meta:
    description = "datamaliciousorder - file 20160309_6c87ac5dd9bab6cd1988209931478134.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de1a472dda58695d9f007cb46299101e27fe84dd8c9522432a08c195dc81069"

  strings:
    $s1  = "defaultValue[colgroup + resolveWith](overrideMimeType + subordinate, rdisplayswap + stopOnFalse + nextAll + whitespace + colgrou" ascii
    $s2  = "div1[getter + parentOffset + unbind + originalProperties] = (0 | (charset - 20));" fullword ascii
    $s3  = "relatedTarget = isLocal[nodeName + udataOld + isXMLDoc + types + getElementsByName + elemData](inspected + setMatchers + isImmed" ascii
    $s4  = "pageX))) * (((Math.pow((Math.pow(178, events) - 31475), (events | 0)) - (simulate & 65535)), ((td + 183) & (Math.pow(_evalUrl, 2" ascii
    $s5  = ") - special)), ((Math.pow(80, events) - 6301) & (col | 111)), (isHidden & 1)) + ((register & 2) & (isHidden * 3))) > reset));" fullword ascii
    $s6  = "eventHandle[preMap + useCache + actualDisplay](relatedTarget, (fixHook, 227, animation, 2));" fullword ascii
    $s7  = "clazz[timeout + margin + rrun][iframe](((val / 43) + (boolHook | 907)));" fullword ascii
    $s8  = "unwrap = \"syst\", tfoot = \"/log\", preMap = \"sav\", getElementsByName = \"Strin\", margin = \"c\";" fullword ascii
    $s9  = "eventHandle = clazz[inArray + unbind][escapedWhitespace + adown + ready + complete](ridentifier + sourceIndex + byElement + offs" ascii
    $s10 = "defaultValue[colgroup + resolveWith](overrideMimeType + subordinate, rdisplayswap + stopOnFalse + nextAll + whitespace + colgrou" ascii
    $s11 = "eventHandle = clazz[inArray + unbind][escapedWhitespace + adown + ready + complete](ridentifier + sourceIndex + byElement + offs" ascii
    $s12 = "p + rfocusable + unwrap + old + tfoot + defer + hooks + properties + optSelected, !(((onreadystatechange * 2 * register / (13 + " ascii
    $s13 = "rnamespace = clazz[conv + elements + unbind];" fullword ascii
    $s14 = "parent = \"durat\"," fullword ascii
    $s15 = "var getter = \"pos\"," fullword ascii
    $s16 = "rtrim = \"se\", after = \"Shell\", ready = \"ateObj\", pixelPositionVal = \"%/\";" fullword ascii
    $s17 = "iatePropagationStopped + pixelPositionVal) + parent + originalProperties + removeData;" fullword ascii
    $s18 = "rjsonp[sort + evt]();" fullword ascii
    $s19 = "clazz = ((9 + (oldfire)), (((249, pattern, 173, charset), (213 & siblings), 11, (events & 2)), this));" fullword ascii
    $s20 = "eventHandle[orig + curValue + adown](onlyHandlers);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}