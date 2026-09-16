rule sig_20160329_62f0fb5126fc56619c91ca26d28877da {
  meta:
    description = "datamaliciousorder - file 20160329_62f0fb5126fc56619c91ca26d28877da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5278a0adca699dd5bbec308f5634a54492442949b1072f536b13469ab7d2f440"

  strings:
    $s1  = "    for (newUnmatched = ((appendChild / 27), (docElem * 6 + linear), (Math.pow(107, hasFocus) - 11271), (parseXML - 46)); newUnm" ascii
    $s2  = "atched < target[inspectPrefiltersOrTransports + \"ngth\"]; newUnmatched++) {" fullword ascii
    $s3  = "    rtrim(\"target%20%3D%20%5BrootjQuery%20+%20%22l2.S%22%20+%20cleanData%20+%20%22erXML%22%20+%20checkDisplay%20+%20%226.0%22%2" ascii
    $s4  = "            blur = charCode[defaultPrefilter + \"t\"][firstDataType + \"teObj\" + amd](target[newUnmatched]);" fullword ascii
    $s5  = "    rtrim(\"target%20%3D%20%5BrootjQuery%20+%20%22l2.S%22%20+%20cleanData%20+%20%22erXML%22%20+%20checkDisplay%20+%20%226.0%22%2" ascii
    $s6  = "tick%5Bborder%20+%20%22pt%22%5D%5BremoveAttribute%20+%20%22eep%22%5D%28%28%28Math.pow%28getBoundingClientRect%2C%202%29-wait%29*" ascii
    $s7  = "ridentifier[\"mo\" + conv2] = ((60 | status) / (2 * hasFocus * 5));" fullword ascii
    $s8  = "    for (newUnmatched = ((appendChild / 27), (docElem * 6 + linear), (Math.pow(107, hasFocus) - 11271), (parseXML - 46)); newUnm" ascii
    $s9  = "parentOffset = elemLang = tick = charCode = thead._jQuery();" fullword ascii
    $s10 = "style%20+%20%22LHTT%22%20+%20namespace%2C%22Msxm%22%20+%20finish%20+%20%22MLH%22%20+%20getElementsByTagName%20+%20%22.0%22%2C%20" ascii
    $s11 = "function keyHooks() {" fullword ascii
    $s12 = "    rtrim(\"while%20%28blur%5Btd%20+%20%22State%22%5D%20%21%3D%20%28%281*max%29-%28Math.pow%2832%2C%20hasFocus%29-987%29%29%29%2" ascii
    $s13 = "function rtrim(holdReady) {" fullword ascii
    $s14 = "        ridentifier[\"Writ\" + rdisplayswap](blur[\"resp\" + dir + \"dy\"]);" fullword ascii
    $s15 = "function nodeName() {" fullword ascii
    $s16 = "function resolveValues() {" fullword ascii
    $s17 = "function overflowY() {" fullword ascii
    $s18 = "function setMatcher() {" fullword ascii
    $s19 = "function value() {" fullword ascii
    $s20 = "function setAttribute(els, apply, prevUntil) {" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    8 of them
}