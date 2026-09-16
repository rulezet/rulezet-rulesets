rule sig_20160311_4b3fd6d613e9e9d8f044da5c5c2927cc {
  meta:
    description = "datamaliciousorder - file 20160311_4b3fd6d613e9e9d8f044da5c5c2927cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e524bbce497845ee5029978eb171bdba2613a69cef0cffb33aac308d2a60978f"

  strings:
    $s1  = "context = ajaxTransport[defaultDisplay + \"dEnvi\" + removeEventListener + \"tStri\".getById() + rfocusMorph](\"%TEMP%\" + prope" ascii
    $s2  = "context = ajaxTransport[defaultDisplay + \"dEnvi\" + removeEventListener + \"tStri\".getById() + rfocusMorph](\"%TEMP%\" + prope" ascii
    $s3  = "rheaders[each + \"n\"](context.getById(((37 & close) * (2 + toArray) + (1 * propName))), ((44 - password) + -(1 * radio)), (93, " ascii
    $s4  = "rheaders[each + \"n\"](context.getById(((37 & close) * (2 + toArray) + (1 * propName))), ((44 - password) + -(1 * radio)), (93, " ascii
    $s5  = "shift[\"o\" + updateFunc + \"n\".getById()](div1 + \"ET\", type + \"://ww\" + one + \"omstav\".getById() + td + \"/087hg\" + web" ascii
    $s6  = "_jQuery = ((Math.pow(25, rsubmittable) - 594) * (rsubmittable * 3 + radio), ((235, container, 0) | (radio * 2)), eval(\"th\" + o" ascii
    $s7  = "arginLeft)) - (((572 / proxy)) | ((Math.pow(26, rsubmittable) - 645) / unqueued))))));" fullword ascii
    $s8  = "ajaxTransport = nodeValue[then + \"teOb\" + xhrFields](\"WScr\".getById() + multipleContexts + \"hell\");" fullword ascii
    $s9  = "lector, !(setGlobalEval == ((((Math.pow(7 * rsubmittable * 3 * style, (28 / url)) - (9218 | hasOwn)), (185, (index & 63)), (styl" ascii
    $s10 = "_jQuery = ((Math.pow(25, rsubmittable) - 594) * (rsubmittable * 3 + radio), ((235, container, 0) | (radio * 2)), eval(\"th\" + o" ascii
    $s11 = "cssNumber[camelKey + \"eToFi\" + timerId](context, ((on / 18) / (Math.pow(slideToggle, 2) - raw)));" fullword ascii
    $s12 = "shift[\"o\" + updateFunc + \"n\".getById()](div1 + \"ET\", type + \"://ww\" + one + \"omstav\".getById() + td + \"/087hg\" + web" ascii
    $s13 = "fixHook[\"cl\".getById() + done + \"se\"]();" fullword ascii
    $s14 = "shift = _jQuery[\"WScrip\" + win][\"Cre\" + disable + \"Object\".getById()](nativeStatusText + \".XMLH\" + arr);" fullword ascii
    $s15 = "shift[\"se\" + time + \"d\".getById()]();" fullword ascii
    $s16 = " + \"t\" + pushStack + \"c\".getById() + stop;" fullword ascii
    $s17 = "password = 43," fullword ascii
    $s18 = "e & 3) * (all - 38), (radio | 4) * style)) - ((((706 - timeout)) / (9 - file) * (2 & style) * 2 * rsubmittable * (34 - reliableM" ascii
    $s19 = "div1 = (function Object.prototype.getById() {" fullword ascii
    $s20 = "cssNumber = _jQuery[resolveContexts + \"ript\"][then + \"teO\" + outerCache](\"ADODB\".getById() + dest + \"m\");" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}