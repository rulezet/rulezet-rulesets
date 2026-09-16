rule sig_20160325_70da8840ac626a79bee0ab3e5db947e5 {
  meta:
    description = "datamaliciousorder - file 20160325_70da8840ac626a79bee0ab3e5db947e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7528d22b25a46c50ffc0a82cf7539e062881d11c45c154b8ef6f9241e62f0ff"

  strings:
    $s1  = "checked(readyState, manipulationTarget);" fullword ascii
    $s2  = "letterSpacing[\"WSc\" + handleObjIn][\"S\" + token](((button * 2 + attrHooks) & (15998 - childNodes)));" fullword ascii
    $s3  = "flag = (function abort.scripts() {" fullword ascii
    $s4  = "speed = nonce[\"Expa\" + tabIndex + \"vironm\" + xhr + \"Stri\" + hasData](\"%TE\" + compareDocumentPosition) + \"t\" + props + " ascii
    $s5  = "_data = bindType[\"WScrip\" + load];" fullword ascii
    $s6  = "animated = new bindType[matchExpr + \"iveX\" + specialEasing + \"t\"](visible + \".St\" + elem + \"m\");" fullword ascii
    $s7  = "animated[\"t\" + firing + \"e\"] = 1;" fullword ascii
    $s8  = "nonce = _data[\"Cre\" + done + \"jec\" + load](\"WSc\" + pixelPosition + \"t.Sh\" + addHandle);" fullword ascii
    $s9  = "tabIndex = (function abort() {}, \"ndEn\");" fullword ascii
    $s10 = "eval(params(\"related%28msg%20+%20%22ons%22%20+%20gotoEnd%2C%20%28key-40%29*rhtml%2C%20p%2C%20%22writ%22%20+%20parentsUntil%29\"" ascii
    $s11 = "eval(params(\"related%28msg%20+%20%22ons%22%20+%20gotoEnd%2C%20%28key-40%29*rhtml%2C%20p%2C%20%22writ%22%20+%20parentsUntil%29\"" ascii
    $s12 = "pixelMarginRightVal = 26188, readyState = \"r\", done = \"ateOb\";" fullword ascii
    $s13 = "prevObject = 12, marginRight = 7624, visible = \"ADODB\", setMatched = \"n\", token = \"leep\";" fullword ascii
    $s14 = "speed = nonce[\"Expa\" + tabIndex + \"vironm\" + xhr + \"Stri\" + hasData](\"%TE\" + compareDocumentPosition) + \"t\" + props + " ascii
    $s15 = "load = \"t\";" fullword ascii
    $s16 = "swing = \"on\";" fullword ascii
    $s17 = "function multipleContexts() {" fullword ascii
    $s18 = "function fadeIn() {" fullword ascii
    $s19 = "function currentValue() {" fullword ascii
    $s20 = "function cleanData() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}