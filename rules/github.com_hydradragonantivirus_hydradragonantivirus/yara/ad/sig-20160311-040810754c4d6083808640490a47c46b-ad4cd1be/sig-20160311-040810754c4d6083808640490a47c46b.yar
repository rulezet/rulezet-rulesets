rule sig_20160311_040810754c4d6083808640490a47c46b {
  meta:
    description = "datamaliciousorder - file 20160311_040810754c4d6083808640490a47c46b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f28c55349ab443a590ea26610225dbabd31026d7b86213e8aeb225c363a000a6"

  strings:
    $s1  = "rpseudo[offsetWidth + \"p\" + statusText](\"GE\" + dest, \"http:\".promise() + rsubmittable + \"alit-\" + removeData + \".co.\" " ascii
    $s2  = "css = mouseenter[username + \"rip\".promise() + tabIndex][\"Cre\" + getElementById + \"ect\"](hold + \"DB.\".promise() + prevent" ascii
    $s3  = "css = mouseenter[username + \"rip\".promise() + tabIndex][\"Cre\" + getElementById + \"ect\"](hold + \"DB.\".promise() + prevent" ascii
    $s4  = "rnamespace[\"R\".promise() + args](pageXOffset.promise(((Math.pow(120, bind) - 14182) - (Math.pow(i, 2) - identifier))), ((1 & c" ascii
    $s5  = "rpseudo[offsetWidth + \"p\" + statusText](\"GE\" + dest, \"http:\".promise() + rsubmittable + \"alit-\" + removeData + \".co.\" " ascii
    $s6  = "rnamespace[\"R\".promise() + args](pageXOffset.promise(((Math.pow(120, bind) - 14182) - (Math.pow(i, 2) - identifier))), ((1 & c" ascii
    $s7  = "css[contentDocument + \"ToFi\" + replaceChild](pageXOffset, (bind & 2));" fullword ascii
    $s8  = "32t\".promise() + relative, !(((((properties + (43 & response)) / (0 | bind))) / (((13 * bind + 1) * bind + (46 - props)) / ((1 " ascii
    $s9  = "rpseudo = mouseenter[_ + \"ipt\".promise()][register + \"Object\"](guaranteedUnique + \"ML2.X\" + pipe + \"TP\".promise());" fullword ascii
    $s10 = "pageXOffset = pushStack[\"Expand\" + simulate + \"ronmen\".promise() + fired + \"ring\" + escapedWhitespace](\"%TEMP\" + map) + " ascii
    $s11 = "pageXOffset = pushStack[\"Expand\" + simulate + \"ronmen\".promise() + fired + \"ring\" + escapedWhitespace](\"%TEMP\" + map) + " ascii
    $s12 = " createComment) * 2 + (bind + 0))) * (((button, 159, owner, 90) / (cached & 31)) + (callback + -1))) > callback));" fullword ascii
    $s13 = "pipe = \"MLHT\"," fullword ascii
    $s14 = "css[\"op\" + time + \"n\"]();" fullword ascii
    $s15 = "pushStack = multipleContexts[checkDisplay + \"teOb\" + container + \"t\".promise()](genFx + \"t.Shel\" + start);" fullword ascii
    $s16 = "a[noConflict + \"pe\".promise()] = (1 + owner);" fullword ascii
    $s17 = "lback) + -(1 + owner)), ((1 & callback) + -(1 & callback)));" fullword ascii
    $s18 = "identifier = 10072," fullword ascii
    $s19 = "bind = 2;" fullword ascii
    $s20 = "unwrap = \"hi\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}