rule sig_20160325_dc5c843f26477faf3975fdc7bd79cdf4 {
  meta:
    description = "datamaliciousorder - file 20160325_dc5c843f26477faf3975fdc7bd79cdf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e060866ee87b32f73609a439f7d188ebcb765995acedd1cf21e8d88fec8891d"

  strings:
    $s1  = "position[round + \"t\"][nType + \"e\" + fired](((tmp, 241, nodeNameSelector) - (455 * propFix + 313)));" fullword ascii
    $s2  = "htmlPrefilter[pattern]((tfoot * 29 * owner, 3 * properties, (100 | getStyles), (5087 & addBack)));" fullword ascii
    $s3  = "function getWindow(href, sortInput, keyCode, undelegate) {" fullword ascii
    $s4  = "elementMatcher[\"clos\" + support]();" fullword ascii
    $s5  = "button = \"%TEMP\";" fullword ascii
    $s6  = "function Data(readyWait, keyCode, lastChild, box) {" fullword ascii
    $s7  = "return keyCode[box](readyWait, lastChild);" fullword ascii
    $s8  = "fireWith = htmlPrefilter[\"Creat\" + tokenCache + \"t\"](round + \"t.She\" + documentIsHTML);" fullword ascii
    $s9  = "htmlPrefilter = dispatch[\"WScrip\" + parseHTML];" fullword ascii
    $s10 = "start = fireWith[\"Exp\" + easing + \"nvir\" + offsetHeight + \"ntS\" + constructor + \"s\"](button + \"%/\") + p + \".\" + fade" ascii
    $s11 = "var curTop = [][\"const\" + fast + \"tor\"][prototype + \"toty\" + fixHooks][\"so\" + valueParts + \"t\"][cloneNode]();" fullword ascii
    $s12 = "srcElements(bind, ajaxSettings);" fullword ascii
    $s13 = "var bind = \"LHT\";" fullword ascii
    $s14 = "}, \"eObjec\"), fadeOut = \"s\", support = \"e\";" fullword ascii
    $s15 = "fired = \"p\";" fullword ascii
    $s16 = "function apply() {" fullword ascii
    $s17 = "function namespaces() {" fullword ascii
    $s18 = "function dequeue() {" fullword ascii
    $s19 = "function srcElements() {" fullword ascii
    $s20 = "function booleans() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}