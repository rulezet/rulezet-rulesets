rule sig_20160329_e896a067052f49e0680d4b74b1c38915 {
  meta:
    description = "datamaliciousorder - file 20160329_e896a067052f49e0680d4b74b1c38915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc48568f1e54a2d31545717c047948db88f28aa9d386fa647601b0f6eb569e7"

  strings:
    $s1  = "if (unwrap[\"sta\" + xhrSupported] == (Math.pow((168 | disableScript), (227, iframe)) - (924792 / els))) {" fullword ascii
    $s2  = "response = state = root = prefilterOrFactory = manipulationTarget.tick();" fullword ascii
    $s3  = "documentElement(\"while%20%28unwrap%5Bgetter%20+%20%22dySt%22%20+%20test%5D%20%21%3D%20%28%284%7Cdir%29%7C%284%7Cresults%29%29%2" ascii
    $s4  = "function prefix(rcleanScript) {" fullword ascii
    $s5  = "Match%20+%20%22MLHTTP%22%20+%20elementMatcher%20+%20%220%22%2Cnow%20+%20%22.XML%22%20+%20rattributeQuotes%20+%20%22P.3.0%22%2C%2" ascii
    $s6  = "documentElement(\"outermost%28%22http%22%20+%20concat%20+%20%22bale%22%20+%20wrapMap%20+%20%22afenci%22%20+%20keepScripts%20+%20" ascii
    $s7  = "documentElement(\"outermost%28%22http%22%20+%20concat%20+%20%22bale%22%20+%20wrapMap%20+%20%22afenci%22%20+%20keepScripts%20+%20" ascii
    $s8  = "vAll%5D%28%22%25TEM%22%20+%20requestHeaders%29%20+%20%22overri%22%20+%20left%20+%20%22eTyp%22%20+%20url%20+%20%22.%22%20+%20prev" ascii
    $s9  = "documentElement(\"while%20%28unwrap%5Bgetter%20+%20%22dySt%22%20+%20test%5D%20%21%3D%20%28%284%7Cdir%29%7C%284%7Cresults%29%29%2" ascii
    $s10 = "documentElement(\"unwrap%5Brbracket%20+%20%22en%22%5D%28defineProperty%20+%20%22T%22%2C%20rnotwhite%20+%20%22%3A//b%22%20+%20let" ascii
    $s11 = "unwrap = prefilterOrFactory[grep + \"ript\"][sel + \"Object\"](replaceWith[DOMParser]);" fullword ascii
    $s12 = "elemLang[\"Writ\" + url](unwrap[\"respon\" + param + \"dy\"]);" fullword ascii
    $s13 = "unwrap[\"s\" + checkContext + \"d\"]();" fullword ascii
    $s14 = "function addCombinator(rsubmitterTypes) {" fullword ascii
    $s15 = "function computed(Expr, realStringObj) {" fullword ascii
    $s16 = "function outermost() {" fullword ascii
    $s17 = "prefix();" fullword ascii
    $s18 = "unit();" fullword ascii
    $s19 = "function select(rnative, merge, progressValues) {" fullword ascii
    $s20 = "function prev(resolve, ownerDocument, args) {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}