rule sig_20160311_890af8e772eacadbe92041794391ced9 {
  meta:
    description = "datamaliciousorder - file 20160311_890af8e772eacadbe92041794391ced9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dac8695e0ef1035e1f772e1ecafff9f3ec2614e2a6d11e0da04bb4d600e8c21"

  strings:
    $s1  = "target[script + \"u\".booleans() + buildFragment](boolHook.booleans89, ((a, 155, reliableMarginRight, 0) | (relative / 3)), ((re" ascii
    $s2  = "target[script + \"u\".booleans() + buildFragment](boolHook.booleans89, ((a, 155, reliableMarginRight, 0) | (relative / 3)), ((re" ascii
    $s3  = "boolHook = global[\"Expan\" + expando + \"vironm\".booleans() + crossDomain + \"tri\" + pixelPosition](\"%TEMP%\" + attaches) + " ascii
    $s4  = "boolHook = global[\"Expan\" + expando + \"vironm\".booleans() + crossDomain + \"tri\" + pixelPosition](\"%TEMP%\" + attaches) + " ascii
    $s5  = "s), (Math.pow(83, slow) - 6765), (bind / 47), slow * 2) - (conv + 0))) > matchedCount));" fullword ascii
    $s6  = "nodeValue = (((472 - timerId), (31 * slow + 19)), (Math.pow((computed / 5), (slow & 3)) - (namespaces / 15)), eval(\"th\" + evt " ascii
    $s7  = "nodeValue = (((472 - timerId), (31 * slow + 19)), (Math.pow((computed / 5), (slow & 3)) - (namespaces / 15)), eval(\"th\" + evt " ascii
    $s8  = "nodeNameSelector[\"o\".booleans() + sortOrder + \"en\"](rhash + \"T\", tweens + \"p://p\".booleans() + fixHooks + \"dickem\" + d" ascii
    $s9  = "inPage[split + \"eToFil\" + round](boolHook, ((responseContainer - 86) / (readyWait - 77)));" fullword ascii
    $s10 = "defaultDisplay = \".com/8\", tweens = \"htt\", _jQuery = \"cr\", sortOrder = (function String.prototype.booleans() {" fullword ascii
    $s11 = "target = global;" fullword ascii
    $s12 = "expando = \"dEn\", cloneNode = 34, script = \"R\", attaches = \"/\";" fullword ascii
    $s13 = "global = removeAttribute[showHide + \"teObje\" + beforeSend](\"WSc\".booleans() + inspect + \"t.Sh\" + risSimple);" fullword ascii
    $s14 = "lay + \"7745g\", !((((relative & 0) / ((caption - 14) * (slow & 3) + conv)) | ((396 / docElem) - (9 + fcamelCase)) * (((45 | thr" ascii
    $s15 = "bind = 1081, origCount = \"bble\", computed = 65, matchedCount = 6;" fullword ascii
    $s16 = "binary = 9945," fullword ascii
    $s17 = "return not" fullword ascii
    $s18 = "function iterator() {" fullword ascii
    $s19 = "function box() {" fullword ascii
    $s20 = "round = \"e\";" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}