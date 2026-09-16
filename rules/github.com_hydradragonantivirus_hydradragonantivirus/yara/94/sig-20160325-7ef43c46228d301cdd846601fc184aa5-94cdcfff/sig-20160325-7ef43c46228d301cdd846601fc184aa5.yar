rule sig_20160325_7ef43c46228d301cdd846601fc184aa5 {
  meta:
    description = "datamaliciousorder - file 20160325_7ef43c46228d301cdd846601fc184aa5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3353f1b1744e0f4a3e5d096246bc19b0ef574e9b1e88f83c80fce39899bdd5d5"

  strings:
    $s1  = "b = excess[pixelMarginRightVal + \"dEnvir\" + structure + \"ntStr\" + filters](\"%TEMP%\" + s) + \"dirrun\" + augmentWidthOrHeig" ascii
    $s2  = "preventDefault[\"Sleep\"](((8565 - delegateTarget) & (79807 / padding)));" fullword ascii
    $s3  = "b = excess[pixelMarginRightVal + \"dEnvir\" + structure + \"ntStr\" + filters](\"%TEMP%\" + s) + \"dirrun\" + augmentWidthOrHeig" ascii
    $s4  = "    targets[\"ty\" + compareDocumentPosition + \"e\"] = ((1 + open) | (39 / cloneNode));" fullword ascii
    $s5  = "    targets = new timeout[removeAttribute + \"XObjec\" + undelegate](\"ADOD\" + high + \"ream\");" fullword ascii
    $s6  = "excess = preventDefault[\"Creat\" + originalEvent + \"t\"](holdReady + \"rip\" + i + \"l\");" fullword ascii
    $s7  = "    getById(module, root, setRequestHeader, compareDocumentPosition, ajaxSetup);" fullword ascii
    $s8  = "root = \"ody\", attr = 40, removeAttribute = \"Active\", i = \"t.Shel\", onerror = \"ply\", parseHTML = 45;" fullword ascii
    $s9  = "function content() {" fullword ascii
    $s10 = "setRequestHeader = \"litech\", valueIsBorderBox = \"e\", structure = \"onme\";" fullword ascii
    $s11 = "content(parseHTML);" fullword ascii
    $s12 = "        var multipleContexts = [][\"const\" + type + \"r\"][addCombinator + \"ype\"][augmentWidthOrHeight + \"o\" + urlAnchor][" ascii
    $s13 = "function getById() {" fullword ascii
    $s14 = "isPlainObject[\"se\" + owner]();" fullword ascii
    $s15 = "error]();" fullword ascii
    $s16 = "        var multipleContexts = [][\"const\" + type + \"r\"][addCombinator + \"ype\"][augmentWidthOrHeight + \"o\" + urlAnchor][" ascii
    $s17 = "    outermost(root, onerror, onerror);" fullword ascii
    $s18 = "function outermost() {" fullword ascii
    $s19 = "function qualifier() {" fullword ascii
    $s20 = "function ontype() {" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}