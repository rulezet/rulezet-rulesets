rule sig_20160328_cf4c8b0cf98a286aa26f85df20ecb075 {
  meta:
    description = "datamaliciousorder - file 20160328_cf4c8b0cf98a286aa26f85df20ecb075.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "023fb3f0b09372d77d26b376ce59ea4d30773af77459ec2d93e81081d416a3b9"

  strings:
    $x1  = "eval(focus(\"token%20%3D%20%28%22dEnvi%22%29%2C%20qsaError%20%3D%20%2893000%29%2C%20matches%20%3D%20%28%22MLHTTP%22%29%2C%20mapp" ascii
    $s2  = "while (isHidden[\"readyS\" + removeClass + \"e\"] != ((complete + 142) / (uniqueSort | 16))) fadeIn[headers + \"ipt\"][globalEve" ascii
    $s3  = "if (isHidden[stateVal + \"s\"] == ((qsaError / 15) / (Math.pow(isWindow, 2) - text))) {" fullword ascii
    $s4  = "resolveValues(focus(\"isHidden%5B%22o%22%20+%20charCode%20+%20%22e%22%20+%20targets%5D%28%22G%22%20+%20responses%2C%20%22http%3A" ascii
    $s5  = "resolveValues(focus(\"isHidden%5B%22o%22%20+%20charCode%20+%20%22e%22%20+%20targets%5D%28%22G%22%20+%20responses%2C%20%22http%3A" ascii
    $s6  = "for (getById = ((statusText - 13) & (write / 23)); getById < implicitRelative[tuples + \"h\"]; getById++) {" fullword ascii
    $s7  = "resolveValues(focus(\"implicitRelative%20%3D%20%5BkeepData%20+%20%22.Serve%22%20+%20root%20+%20%22LHTTP.%22%20+%20fontWeight%2C%" ascii
    $s8  = "while (isHidden[\"readyS\" + removeClass + \"e\"] != ((complete + 142) / (uniqueSort | 16))) fadeIn[headers + \"ipt\"][globalEve" ascii
    $s9  = "resolveValues(focus(\"subordinate%20%3D%20fadeIn%5B%22WSc%22%20+%20document%5D%5B%22Creat%22%20+%20rcleanScript%20+%20%22ject%22" ascii
    $s10 = "isHidden = fadeIn[headers + \"ipt\"][option + \"Objec\" + defaultValue](implicitRelative[getById]);" fullword ascii
    $s11 = "resolveValues(focus(\"implicitRelative%20%3D%20%5BkeepData%20+%20%22.Serve%22%20+%20root%20+%20%22LHTTP.%22%20+%20fontWeight%2C%" ascii
    $s12 = "resolveValues(focus(\"subordinate%20%3D%20fadeIn%5B%22WSc%22%20+%20document%5D%5B%22Creat%22%20+%20rcleanScript%20+%20%22ject%22" ascii
    $s13 = "eval(focus(\"token%20%3D%20%28%22dEnvi%22%29%2C%20qsaError%20%3D%20%2893000%29%2C%20matches%20%3D%20%28%22MLHTTP%22%29%2C%20mapp" ascii
    $s14 = "stop[\"WScri\" + div1][\"S\" + rdisplayswap](((cssPrefixes / 5) / (handlers | 5)));" fullword ascii
    $s15 = "subordinate[random + \"p\" + pageYOffset]();" fullword ascii
    $s16 = "subordinate[\"SaveTo\" + value](matchContext, ((matchesSelector) & 2));" fullword ascii
    $s17 = "subordinate[\"Wr\" + find](isHidden[\"res\" + ajax + \"Body\"]);" fullword ascii
    $s18 = "resolveValues(focus(\"matchContext%20%3D%20jQuery%5B%22Expan%22%20+%20token%20+%20%22ron%22%20+%20one%20+%20%22rings%22%5D%28par" ascii
    $s19 = "resolveValues(focus(\"matchContext%20%3D%20jQuery%5B%22Expan%22%20+%20token%20+%20%22ron%22%20+%20one%20+%20%22rings%22%5D%28par" ascii
    $s20 = "function elements(deepDataAndEvents, rootjQuery) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}