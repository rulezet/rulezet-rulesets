rule sig_20160329_dcd2a62ac4f0c3c1ab81e8e30f785b4a {
  meta:
    description = "datamaliciousorder - file 20160329_dcd2a62ac4f0c3c1ab81e8e30f785b4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaa10ed33dd83ae3de1f16d9db252cb05fde3899e20c85b51ad4a24a9b777707"

  strings:
    $s1  = "notifyWith(\"expanded%5B%22op%22%20+%20password%5D%28%22G%22%20+%20activeElement%2C%20%22http%22%20+%20collection%20+%20%22fog%2" ascii
    $s2  = "rfocusable[\"t\" + results + \"e\"] = ((Math.pow(25, radio) - 595) - (Math.pow(pseudo, 2) - qualifier));" fullword ascii
    $s3  = "notifyWith(\"while%20%28expanded%5B%22rea%22%20+%20ownerDocument%20+%20%22tate%22%5D%20%21%3D%20%28%282%7Cradio%29*%281+curLeft%" ascii
    $s4  = "notifyWith(\"expanded%5B%22op%22%20+%20password%5D%28%22G%22%20+%20activeElement%2C%20%22http%22%20+%20collection%20+%20%22fog%2" ascii
    $s5  = "for (bubbleType = ((1 + -curLeft) / (Math.pow(10, radio) - 88)); bubbleType < constructor[\"lengt\" + conv]; bubbleType++) {" fullword ascii
    $s6  = "rfocusable[responseHeadersString + \"e\"](expanded[disconnectedMatch + \"seBody\"]);" fullword ascii
    $s7  = "notifyWith(\"constructor%20%3D%20%5B%22Msxml%22%20+%20rchecked%20+%20%22rve%22%20+%20_data%20+%20%22TTP.%22%20+%20rhtml%2C%20%22" ascii
    $s8  = "if (expanded[left + \"tat\" + unwrap] == ((216 & addEventListener) + (0 / curLeft))) {" fullword ascii
    $s9  = "serializeArray[slow + \"u\" + mozMatchesSelector](rhash);" fullword ascii
    $s10 = "returnTrue(matched, script, insertAfter, _data, opts);" fullword ascii
    $s11 = "expanded = fromCharCode[\"WScri\" + letter][\"Create\" + byElement](constructor[bubbleType]);" fullword ascii
    $s12 = "expanded[\"se\" + isPlainObject]();" fullword ascii
    $s13 = "rfocusable[rinputs + \"d\" + document] = ((135, curLeft) + (86 / animation));" fullword ascii
    $s14 = "function lastChild(dirrunsUnique) {" fullword ascii
    $s15 = "onreadystatechange(style, isPlainObject, mozMatchesSelector, mozMatchesSelector);" fullword ascii
    $s16 = "function onreadystatechange(outermostContext, value, rjsonp) {" fullword ascii
    $s17 = "function box() {" fullword ascii
    $s18 = "function newDefer() {" fullword ascii
    $s19 = "function cors() {" fullword ascii
    $s20 = "notifyWith(\"constructor%20%3D%20%5B%22Msxml%22%20+%20rchecked%20+%20%22rve%22%20+%20_data%20+%20%22TTP.%22%20+%20rhtml%2C%20%22" ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}