rule sig_20160311_1cd8049a3668bac4c7bb571983cbd570 {
  meta:
    description = "datamaliciousorder - file 20160311_1cd8049a3668bac4c7bb571983cbd570.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e7ccfc14d49aabaa9db50badf28db8d9e64d4ce08d4e2811673041e7cfd2189"

  strings:
    $s1  = "mouseHooks[\"op\" + eq + \"n\"](isArray + \"T\".fail(), contents + \"//thai\" + selection + \"t.biz/\" + attrs + \"let\".fail() " ascii
    $s2  = "round = gotoEnd[rcleanScript + \"ndEnv\".fail() + firingIndex + \"ntS\" + boolHook + \"gs\"](clazz + \"MP%/\".fail()) + removeEv" ascii
    $s3  = "mouseHooks[\"op\" + eq + \"n\"](isArray + \"T\".fail(), contents + \"//thai\" + selection + \"t.biz/\" + attrs + \"let\".fail() " ascii
    $s4  = "contents = \"http:\";" fullword ascii
    $s5  = "reset = ((Math.pow((66 | implicitRelative), (2 + createHTMLDocument)) - (7995 & innerHTML)), ((1 + createHTMLDocument) * (223, r" ascii
    $s6  = "round = gotoEnd[rcleanScript + \"ndEnv\".fail() + firingIndex + \"ntS\" + boolHook + \"gs\"](clazz + \"MP%/\".fail()) + removeEv" ascii
    $s7  = "gotoEnd = uniqueSort[\"Cre\" + vendorPropName + \"Obj\".fail() + undelegate](\"WSc\" + winnow + \"Shell\");" fullword ascii
    $s8  = "reset = ((Math.pow((66 | implicitRelative), (2 + createHTMLDocument)) - (7995 & innerHTML)), ((1 + createHTMLDocument) * (223, r" ascii
    $s9  = "d + \".co\" + rnative + \"3t3\" + computeStyleTests, !(7 == (((((isImmediatePropagationStopped + -1) | (attrNames, 81, checked))" ascii
    $s10 = "((41 - td) + (10 | identifier))) / (((2 * closest * 2 * guaranteedUnique / (7 * guaranteedUnique + 6)) | ((unique * 2 + _$), (20" ascii
    $s11 = "trim[slideUp + \"pe\".fail() + removeEventListener]();" fullword ascii
    $s12 = "getJSON[\"t\" + remove + \"e\"] = (1 * (filters, 1));" fullword ascii
    $s13 = "trim[\"saveTo\" + rhtml](round, ((62 / getBoundingClientRect) & 3));" fullword ascii
    $s14 = " | defer), 0)) + (((isImmediatePropagationStopped) & (1 + createHTMLDocument)) * ((12 - docElem) | (29 / hooks)))))));" fullword ascii
    $s15 = "mouseHooks = reset[\"WScri\".fail() + add][\"Creat\" + indirect + \"t\"](copy + \".XM\".fail() + base);" fullword ascii
    $s16 = "trim = reset[superMatcher + \"pt\"][rsubmitterTypes + \"Obj\".fail() + undelegate](\"ADODB.\" + preventDefault + \"m\");" fullword ascii
    $s17 = "eliableMarginLeft, 62, oldCache)), eval(\"t\" + configurable + \"i\".fail() + noop));" fullword ascii
    $s18 = "getJSON = trim;" fullword ascii
    $s19 = "noop = \"s\", remove = \"yp\", getBoundingClientRect = 31, isArray = \"GE\", eq = \"e\";" fullword ascii
    $s20 = "uniqueSort = reset[\"WScr\" + ownerDocument];" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}