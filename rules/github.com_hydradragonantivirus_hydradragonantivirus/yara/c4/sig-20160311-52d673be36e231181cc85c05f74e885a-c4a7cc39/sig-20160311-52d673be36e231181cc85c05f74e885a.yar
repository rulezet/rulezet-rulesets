rule sig_20160311_52d673be36e231181cc85c05f74e885a {
  meta:
    description = "datamaliciousorder - file 20160311_52d673be36e231181cc85c05f74e885a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "975b41e47316ef3209b0dbcb7fd69ad49e6f4bbeea289c8078e48591983edc1e"

  strings:
    $x1  = "targets[\"op\".init() + sortDetached + \"n\"](isEmptyObject + \"E\" + callbackContext, \"http:\".init() + uniqueID + \"rpyof\" +" ascii
    $s2  = "binary = ((36 / mappedTypes) * (Math.pow(3, constructor) - 4) * constructor * (142, cssHooks, 2), (Math.pow((defer / 4), (pdataO" ascii
    $s3  = "targets = binary[\"WSc\" + iNoClone][\"Creat\".init() + parseXML + \"t\"](window + \".XMLHT\" + merge);" fullword ascii
    $s4  = " 9579760) / (Math.pow(key, 2) - pseudos))) / ((140 / fireWith) | 1) * (constructor & 3)) & ((((chainable | 130), (Math.pow(accep" ascii
    $s5  = "targets[createHTMLDocument + \"e\" + clone + \"d\"]();" fullword ascii
    $s6  = "binary = ((36 / mappedTypes) * (Math.pow(3, constructor) - 4) * constructor * (142, cssHooks, 2), (Math.pow((defer / 4), (pdataO" ascii
    $s7  = "responseHeaders[support + \"yp\".init() + sortDetached] = (1 + pdataOld);" fullword ascii
    $s8  = "ts, 2) - expando)) / ((184 & optgroup), 2)) - (((elemData + 72) / (Math.pow(cssHooks, 2) - curValue)) - ((26 * constructor + 3) " ascii
    $s9  = "push_native[onreadystatechange + \"n\".init()](pageX.init(((20 + detach) + 19)), (isTrigger, 0), (pdataOld));" fullword ascii
    $s10 = "reject = binary[preFilter + \"pt\".init()][v + \"ate\" + eased + \"t\"](cssShow + \"Strea\".init() + selectedIndex);" fullword ascii
    $s11 = "args = binary[\"WScri\" + charCode];" fullword ascii
    $s12 = "String + \"om/67j\" + then + \"4\".init(), !(7 < (((((tick - 40) * (resolveValues) + (11 & rCRLF)) & ((Math.pow(3096, constructo" ascii
    $s13 = "}, \"Cre\"), onreadystatechange = \"Ru\", support = \"t\";" fullword ascii
    $s14 = "responseHeaders = reject;" fullword ascii
    $s15 = "resolveWith[self + \"lose\".init()]();" fullword ascii
    $s16 = "reject[\"op\" + sortDetached + \"n\"]();" fullword ascii
    $s17 = "reject[pageXOffset + \"ToFile\"](pageX, (newSelector / 27));" fullword ascii
    $s18 = "cur = args[\"Cre\" + dest + \"Object\".init()](preFilter + \"pt.\" + box);" fullword ascii
    $s19 = "select();" fullword ascii
    $s20 = "function select() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}