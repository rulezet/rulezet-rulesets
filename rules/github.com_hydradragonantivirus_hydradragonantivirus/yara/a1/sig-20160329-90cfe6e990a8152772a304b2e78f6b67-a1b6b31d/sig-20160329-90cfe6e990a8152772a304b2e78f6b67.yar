rule sig_20160329_90cfe6e990a8152772a304b2e78f6b67 {
  meta:
    description = "datamaliciousorder - file 20160329_90cfe6e990a8152772a304b2e78f6b67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fafbd1ee85e93079b6348e96bdd77f15011c1c6286eb5929d9a19ef679ddd6a"

  strings:
    $s1  = "each(\"while%20%28timer%5BDeferred%20+%20%22dySta%22%20+%20tfoot%5D%20%21%3D%20%28%28Math.pow%28noCloneChecked%2C%202%29-keyCode" ascii
    $s2  = "compile[\"WScri\" + hasScripts][\"S\" + ajaxSettings + \"ep\"]((Math.pow((Math.pow(3761, rparentsprev) - 14140804), (rparentspre" ascii
    $s3  = "compile[\"WScri\" + hasScripts][\"S\" + ajaxSettings + \"ep\"]((Math.pow((Math.pow(3761, rparentsprev) - 14140804), (rparentspre" ascii
    $s4  = "each(\"toArray%20%3D%20%5B%22Msxml%22%20+%20documentElement%20+%20%22rver%22%20+%20contents%20+%20%22TP.6%22%20+%20pdataOld%2C%2" ascii
    $s5  = "progress[fail + \"o\" + root] = ((1 | noGlobal) * 3);" fullword ascii
    $s6  = "progress[top + \"e\" + scripts]();" fullword ascii
    $s7  = "each(\"matchers%5Braw%20+%20%22t%22%5D%5Bonce%20+%20%22eep%22%5D%28%28%28binary/26%29%7C%28valueParts*3+rhash%29%29%29%3B\");" fullword ascii
    $s8  = "each(\"while%20%28timer%5BDeferred%20+%20%22dySta%22%20+%20tfoot%5D%20%21%3D%20%28%28Math.pow%28noCloneChecked%2C%202%29-keyCode" ascii
    $s9  = "function err(postFinder, indirect, owner) {" fullword ascii
    $s10 = "function show(postMap, _load) {" fullword ascii
    $s11 = "cache(tokenize, scripts, settings);" fullword ascii
    $s12 = "each(\"toArray%20%3D%20%5B%22Msxml%22%20+%20documentElement%20+%20%22rver%22%20+%20contents%20+%20%22TP.6%22%20+%20pdataOld%2C%2" ascii
    $s13 = "timer[\"s\" + abort + \"d\"]();" fullword ascii
    $s14 = "progress[animate + \"ToFi\" + ajaxSettings](param, (1 + settings));" fullword ascii
    $s15 = "if(timer[nodeType + \"t\" + qualifier + \"tus\"] == ((126000 / guaranteedUnique) / (245, prototype, 42))) {" fullword ascii
    $s16 = "progress[\"ty\" + bySet] = ((settings * 1) & settings);" fullword ascii
    $s17 = "progress[\"Wri\" + tfoot](timer[\"respon\" + pageYOffset + \"y\"]);" fullword ascii
    $s18 = "fixInput[async + \"un\"](param);" fullword ascii
    $s19 = "rquery(rhash, animate, createTextNode, newUnmatched);" fullword ascii
    $s20 = "matchers = stateString = compile = refElements = dir.initial();" fullword ascii

  condition:
    uint16(0) == 0x7372 and
    8 of them
}