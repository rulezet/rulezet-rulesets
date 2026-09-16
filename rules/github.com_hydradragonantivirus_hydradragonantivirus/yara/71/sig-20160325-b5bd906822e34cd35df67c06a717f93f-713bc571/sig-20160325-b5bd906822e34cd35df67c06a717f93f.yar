rule sig_20160325_b5bd906822e34cd35df67c06a717f93f {
  meta:
    description = "datamaliciousorder - file 20160325_b5bd906822e34cd35df67c06a717f93f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef7a5066ef69927e6918ca03cb5a9f5f7dd6c476cd2ce88655a2359e3e360db"

  strings:
    $s1  = "eval(a(\"type%5B%22op%22%20+%20xhrSupported%5D%28%22G%22%20+%20holdReady%2C%20%22http%22%20+%20node%20+%20%22kan%22%20+%20visibl" ascii
    $s2  = "tmp[\"WScri\" + hasContent][\"Sle\" + until + \"p\"](((escaped - 4067) + (fragment | 2140)));" fullword ascii
    $s3  = "ready = clazz[wrapAll + \"and\" + innerHTML + \"iro\" + deep + \"trings\"](modified + \"%/\") + conv2 + \"rs\" + input + \"s\" +" ascii
    $s4  = "eval(a(\"type%5B%22op%22%20+%20xhrSupported%5D%28%22G%22%20+%20holdReady%2C%20%22http%22%20+%20node%20+%20%22kan%22%20+%20visibl" ascii
    $s5  = "arg[defer + \"ep\"](((32, rheader) * 3 * isXML + (41 & properties)));" fullword ascii
    $s6  = "clazz = arg[rbrace + \"eObje\" + next](\"WScr\" + bindType + \"ell\");" fullword ascii
    $s7  = "type[\"s\" + xhrSupported + \"d\"]();" fullword ascii
    $s8  = "matcherIn = new related[newUnmatched + \"iveX\" + easing + \"ect\"](optDisabled + \".Str\" + sortDetached);" fullword ascii
    $s9  = "var check = [][\"con\" + xhrFields + \"ucto\" + wrapInner][\"protot\" + pipe][\"s\" + handlers + \"r\" + done][\"ap\" + hasClass" ascii
    $s10 = "_jQuery(createPseudo, holdReady, unit, bindType);" fullword ascii
    $s11 = "related = tmp = amd = rts = conv.xml();" fullword ascii
    $s12 = "var pipe = \"ype\"," fullword ascii
    $s13 = "done = \"t\", handlers = \"o\", hasContent = \"pt\", fire = \"ty\", easing = \"Obj\";" fullword ascii
    $s14 = "function props(Deferred, getClientRects, fired, valueParts) {" fullword ascii
    $s15 = "rheader = 551, optionSet = 35, input = \".\", wrapAll = \"Exp\", node = \"://\", fireGlobals = \"ive\";" fullword ascii
    $s16 = "function matchesSelector(elemLang, top, getClientRects, parentWindow) {" fullword ascii
    $s17 = "return getClientRects[valueParts](Deferred, fired);" fullword ascii
    $s18 = "getClientRects[parentWindow](type[elemLang]);" fullword ascii
    $s19 = "arg = rts[\"WSc\" + locked + \"t\"];" fullword ascii
    $s20 = "matcherIn[fire + \"pe\"] = (1 + createPseudo);" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    8 of them
}