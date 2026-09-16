rule sig_20160328_475c5718af688c22a7e8ef185a224574 {
  meta:
    description = "datamaliciousorder - file 20160328_475c5718af688c22a7e8ef185a224574.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d90afcdc10b1624d848b87b7f56d4f073ee0133b7aa85e149a127e6bb9d38030"

  strings:
    $s1  = "tweens[\"mo\" + _removeData + \"e\"] = ((9 - blur));" fullword ascii
    $s2  = "function last(scripts, firstDataType) {" fullword ascii
    $s3  = "pipe*3+left%29%29%29%3B\"));" fullword ascii
    $s4  = "DOMParser(pipe, lname, nodes);" fullword ascii
    $s5  = "initial = fire = success = swing = makeArray.head();" fullword ascii
    $s6  = "    while(whitespace[rnoContent + \"dySta\" + speed] != ((jqXHR & 2) * offset)) success[\"WSc\" + newUnmatched][\"Sl\" + opt]((2" ascii
    $s7  = "otocol + 0) * (offset + 0) * (protocol)));" fullword ascii
    $s8  = "    while(whitespace[rnoContent + \"dySta\" + speed] != ((jqXHR & 2) * offset)) success[\"WSc\" + newUnmatched][\"Sl\" + opt]((2" ascii
    $s9  = "last(newUnmatched, hasFocus, readyWait);" fullword ascii
    $s10 = "register(username);" fullword ascii
    $s11 = "function ajaxHandleResponses(rheader, outerCache) {" fullword ascii
    $s12 = "    for(dataTypeOrTransport = (219, evt); dataTypeOrTransport < delegate[tabIndex]; dataTypeOrTransport++) {" fullword ascii
    $s13 = "    stored(th(\"success%5BnodeType%20+%20%22pt%22%5D%5Bfragment%20+%20%22ep%22%5D%28%28%28apply%2C247%2CfinalText%2C4864%29%7C%2" ascii
    $s14 = "function using() {" fullword ascii
    $s15 = "function not() {" fullword ascii
    $s16 = "function responseContainer(hold) {" fullword ascii
    $s17 = "*protocol*2*protocol*5*offset*2%29%2C%20%28on/24%29%29-%28rmouseEvent+2556342%29%29%29%3B\"));" fullword ascii
    $s18 = "function contains(err, nType) {" fullword ascii
    $s19 = "function th(pixelMarginRightVal) {" fullword ascii
    $s20 = "function DOMParser(appendChild) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}