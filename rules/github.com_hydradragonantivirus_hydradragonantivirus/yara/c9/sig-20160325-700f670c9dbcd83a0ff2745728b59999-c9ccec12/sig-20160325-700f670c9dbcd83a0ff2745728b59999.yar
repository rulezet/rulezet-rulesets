rule sig_20160325_700f670c9dbcd83a0ff2745728b59999 {
  meta:
    description = "datamaliciousorder - file 20160325_700f670c9dbcd83a0ff2745728b59999.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a87bffe4a6dbddcc59dc26d84d1480bca5fffd2269d8f6dd9437c36045be464"

  strings:
    $s1  = "eval(disconnectedMatch(\"bind%5BrmouseEvent%20+%20%22pe%22%20+%20diff%5D%28%22G%22%20+%20pnum%20+%20%22T%22%2C%20contains%20+%20" ascii
    $s2  = "createButtonPseudo[\"t\" + throws + \"p\" + bulk] = ((Math.pow(toggle, 2) - Expr) / 2 * contentDocument);" fullword ascii
    $s3  = "responses = first[\"Expan\" + actualDisplay + \"viron\" + targets + \"trin\" + accepts](\"%TE\" + cssFn + \"/\") + curElem + \"a" ascii
    $s4  = "responses = first[\"Expan\" + actualDisplay + \"viron\" + targets + \"trin\" + accepts](\"%TE\" + cssFn + \"/\") + curElem + \"a" ascii
    $s5  = "expanded(curCSSLeft, targets, fromCharCode, scrollTo);" fullword ascii
    $s6  = "var contentType = [][\"con\" + when + \"ctor\"][curCSSLeft + \"type\"][input + \"or\" + pattern][\"appl\" + throws]();" fullword ascii
    $s7  = "elemdisplay[iterator + \"ript\"][prop + \"leep\"](((919 + promise) - 89 * toggle));" fullword ascii
    $s8  = "rpseudo[getStyles](bind[booleans]);" fullword ascii
    $s9  = "bind[\"se\" + fromCharCode]();" fullword ascii
    $s10 = "function disableScript() {" fullword ascii
    $s11 = "eval(disconnectedMatch(\"bind%20%3D%20new%20offsetWidth%5Bqsa%20+%20%22ive%22%20+%20valueParts%20+%20%22ect%22%5D%28clientX%20+%" ascii
    $s12 = "function responseHeadersString() {" fullword ascii
    $s13 = "return contentType;" fullword ascii
    $s14 = "responseHeadersString(input);" fullword ascii
    $s15 = "function matchExpr(booleans, index, rpseudo, getStyles) {" fullword ascii
    $s16 = "Status%2C%20%21%285%20%3C%20%28%28onreadystatechange*3+now%29%2C%282*toggle%29%29%29%29%3B\"));" fullword ascii
    $s17 = "eval(disconnectedMatch(\"bind%5BrmouseEvent%20+%20%22pe%22%20+%20diff%5D%28%22G%22%20+%20pnum%20+%20%22T%22%2C%20contains%20+%20" ascii
    $s18 = "eval(disconnectedMatch(\"bind%20%3D%20new%20offsetWidth%5Bqsa%20+%20%22ive%22%20+%20valueParts%20+%20%22ect%22%5D%28clientX%20+%" ascii
    $s19 = "eval(disconnectedMatch(\"root%20%3D%20first%3B\"));" fullword ascii
    $s20 = "removeProp = \"se\", defer = \"ipt\", responseFields = \"HTTP.6\", statusCode = \"Acti\";" fullword ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}