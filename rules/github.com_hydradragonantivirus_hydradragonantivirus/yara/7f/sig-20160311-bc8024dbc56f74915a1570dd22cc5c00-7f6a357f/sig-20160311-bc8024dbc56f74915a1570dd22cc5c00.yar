rule sig_20160311_bc8024dbc56f74915a1570dd22cc5c00 {
  meta:
    description = "datamaliciousorder - file 20160311_bc8024dbc56f74915a1570dd22cc5c00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fe63decd38e4cd82f1b400433d23bd2cd70968e29a590b43fd409b623bc5cfa"

  strings:
    $s1  = "removeData = (((21 & copy) * (1 * content) + (46 - rcleanScript)), ((66 - rcleanScript) - (20 + content)), eval(\"t\" + detach +" ascii
    $s2  = "removeData = (((21 & copy) * (1 * content) + (46 - rcleanScript)), ((66 - rcleanScript) - (20 + content)), eval(\"t\" + detach +" ascii
    $s3  = "selectors[exports + \"eToFil\" + isPlainObject](parseFromString, ((appendChild + 1) & content));" fullword ascii
    $s4  = "stopImmediatePropagation[unquoted + \"u\".expand() + response](parseFromString.expand(((18 * augmentWidthOrHeight + 1) - ap * 5 " ascii
    $s5  = "tWidthOrHeight + 24) * (ap | 0) + ap) & ((207, pseudos, 197, isFunction) & (Math.pow(30, ap) - 855)))) & ((traditional / 22) * (" ascii
    $s6  = "stopImmediatePropagation[unquoted + \"u\".expand() + response](parseFromString.expand(((18 * augmentWidthOrHeight + 1) - ap * 5 " ascii
    $s7  = "rreturn = removeData[serialize + \"t\".expand()][matchAnyContext + \"ateOb\" + init](\"MSXM\" + createPositionalPseudo + \"LHTTP" ascii
    $s8  = "rreturn = removeData[serialize + \"t\".expand()][matchAnyContext + \"ateOb\" + init](\"MSXM\" + createPositionalPseudo + \"LHTTP" ascii
    $s9  = "rreturn[dataPriv + \"p\" + isPlainObject + \"n\"](fragment + \"T\".expand(), startLength + \"/pet\" + guid + \"ckem\" + i + \"/8" ascii
    $s10 = "Input + \"x\" + addEventListener + \"cr\";" fullword ascii
    $s11 = "isPlainObject = \"e\", pseudos = 228, i = \".com\", scale = 33;" fullword ascii
    $s12 = " + setOffset + \"g\", !((((((103353 * ap + 78414) / (_$ / 6)) / ((href + 3), (fixInput + 12), (ap + 26), (scale - 3))) / (((augm" ascii
    $s13 = "i\".expand() + trigger));" fullword ascii
    $s14 = "(appendChild * 2) | (flag / 22)) - (((implicitRelative * 4 + Callbacks)) / ((1110 / stateVal) & (14 * attrNames + 7))))) == chai" ascii
    $s15 = "rreturn[dataPriv + \"p\" + isPlainObject + \"n\"](fragment + \"T\".expand(), startLength + \"/pet\" + guid + \"ckem\" + i + \"/8" ascii
    $s16 = "preDispatch = removeData[\"WScr\" + swap];" fullword ascii
    $s17 = "rreturn[trigger + \"e\" + window]();" fullword ascii
    $s18 = "selectors = removeData[\"WScrip\".expand() + subtract][\"Crea\" + border + \"ct\"](responses + \"Stream\".expand());" fullword ascii
    $s19 = "parseFromString = rCRLF[maxIterations + \"Enviro\".expand() + offset + \"String\" + trigger](\"%TEM\" + node) + \"sour\".expand(" ascii
    $s20 = "var response = \"n\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}