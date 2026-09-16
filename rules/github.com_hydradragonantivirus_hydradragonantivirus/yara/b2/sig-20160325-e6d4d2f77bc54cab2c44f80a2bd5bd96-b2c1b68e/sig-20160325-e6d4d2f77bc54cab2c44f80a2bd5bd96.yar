rule sig_20160325_e6d4d2f77bc54cab2c44f80a2bd5bd96 {
  meta:
    description = "datamaliciousorder - file 20160325_e6d4d2f77bc54cab2c44f80a2bd5bd96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d9f0f7817dd71a68829c390582d306195cb7dda5dc490a14dc6c6c268fae478"

  strings:
    $s1  = "eval(progressValues(\"createCache%5BrkeyEvent%20+%20%22e%22%20+%20docElem%5D%28%22G%22%20+%20preDispatch%20+%20%22T%22%2C%20data" ascii
    $s2  = "how%20+%20%22/mal%22%20+%20textContent%20+%20%22nt.sk/%22%20+%20XMLHttpRequest%20+%20%22r.exe%22%2C%20%21%28%2813*version%2C%281" ascii
    $s3  = "finalValue = then[\"Expand\" + hasData + \"onm\" + msg + \"rings\"](sibling + \"%/\") + hasScripts + \"a\" + mouseenter + \"h\" " ascii
    $s4  = "fireGlobals = \"Slee\", async = \"WScrip\", ready = \"WScr\", postSelector = \"c\", preFilters = (function addBack() {}, 11), na" ascii
    $s5  = "chainable(rkeyEvent, Data);" fullword ascii
    $s6  = "key = new err[sortStable + \"veX\" + getElementsByClassName](\"ADODB.\" + disabled + \"am\");" fullword ascii
    $s7  = "detach[async + \"t\"][fireGlobals + \"p\"](((resolveValues & 250), (push_native - 9890)));" fullword ascii
    $s8  = "fireGlobals = \"Slee\", async = \"WScrip\", ready = \"WScr\", postSelector = \"c\", preFilters = (function addBack() {}, 11), na" ascii
    $s9  = "then = colgroup[\"Creat\" + namespaces + \"ct\"](ready + \"ipt.Sh\" + parseOnly);" fullword ascii
    $s10 = "sibling = \"%TEMP\", ajaxSetup = \"ype\", realStringObj = \"le\";;" fullword ascii
    $s11 = "key[\"ty\" + url] = ((w / 32), transport);" fullword ascii
    $s12 = "finalValue = then[\"Expand\" + hasData + \"onm\" + msg + \"rings\"](sibling + \"%/\") + hasScripts + \"a\" + mouseenter + \"h\" " ascii
    $s13 = "function requestHeadersNames() {" fullword ascii
    $s14 = "function getBoundingClientRect() {" fullword ascii
    $s15 = "getBoundingClientRect(tr, clone, old);" fullword ascii
    $s16 = "proxy(getElementsByClassName, hasData);" fullword ascii
    $s17 = "transport = 1;" fullword ascii
    $s18 = "function proxy() {" fullword ascii
    $s19 = "eval(progressValues(\"checkClone%28%22Resp%22%20+%20sort%20+%20%22eBody%22%2C%20%28Math.pow%283*visibility%2C%20%2818/Data%29%29" ascii
    $s20 = "eval(progressValues(\"relative%28finalValue%2C%20key%2C%20%28%28transport*2%29%7C%28eventPath-45%29%29%2C%20%22sav%22%20+%20data" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}