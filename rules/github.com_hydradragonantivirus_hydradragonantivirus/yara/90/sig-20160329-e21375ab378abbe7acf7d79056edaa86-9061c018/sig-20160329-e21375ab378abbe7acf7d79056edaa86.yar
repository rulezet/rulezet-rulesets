rule sig_20160329_e21375ab378abbe7acf7d79056edaa86 {
  meta:
    description = "datamaliciousorder - file 20160329_e21375ab378abbe7acf7d79056edaa86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f43bf4441152ab53286a20e2a83d2fa5c2aa875e9600cd3325b3af7eb3f2201"

  strings:
    $s1  = "prevAll(\"proxy%20%3D%20%5BoMatchesSelector%20+%20%222.Ser%22%20+%20qualifier%20+%20%22LHTT%22%20+%20converters%2C%20%22Msxm%22%" ascii
    $s2  = "if(bindType[uid + \"at\" + linear] == ((2 | returnValue) * (7 - fadeIn) * (Math.pow(3, returnValue) - 4) * (returnValue * 2 + cu" ascii
    $s3  = "if(bindType[uid + \"at\" + linear] == ((2 | returnValue) * (7 - fadeIn) * (Math.pow(3, returnValue) - 4) * (returnValue * 2 + cu" ascii
    $s4  = "lang[\"WScri\" + remaining][\"Slee\" + checked](((Math.pow(parseHTML, 2) - getById) - (8724 / useCache)));" fullword ascii
    $s5  = "bindType = bubbleType[\"WScr\" + tweens][\"Crea\" + unique + \"ject\"](proxy[createDocumentFragment]);" fullword ascii
    $s6  = "for(createDocumentFragment = ((keepData & 0) | keepData); createDocumentFragment < proxy[\"le\" + rsubmitterTypes]; createDocume" ascii
    $s7  = "for(createDocumentFragment = ((keepData & 0) | keepData); createDocumentFragment < proxy[\"le\" + rsubmitterTypes]; createDocume" ascii
    $s8  = "prepend[removeEventListener + \"p\" + statusText] = (sibling / 8);" fullword ascii
    $s9  = "prevAll(\"while%20%28bindType%5B%22rea%22%20+%20querySelectorAll%20+%20%22e%22%5D%20%21%3D%20%28%28opener%2631%29-%28Math.pow%28" ascii
    $s10 = "prevAll(\"proxy%20%3D%20%5BoMatchesSelector%20+%20%222.Ser%22%20+%20qualifier%20+%20%22LHTT%22%20+%20converters%2C%20%22Msxm%22%" ascii
    $s11 = "prevAll(\"while%20%28bindType%5B%22rea%22%20+%20querySelectorAll%20+%20%22e%22%5D%20%21%3D%20%28%28opener%2631%29-%28Math.pow%28" ascii
    $s12 = "function identifier() {" fullword ascii
    $s13 = "bindType[outermostContext + \"e\" + camel]();" fullword ascii
    $s14 = "checkOn(unique, keepData, ready, resolveContexts);" fullword ascii
    $s15 = "prevAll(\"identifier%28%22http%22%20+%20lname%20+%20%22ca.nl%22%20+%20eventHandle%20+%20%22FT.%22%20+%20string%29%3B\");" fullword ascii
    $s16 = "function rdashAlpha() {" fullword ascii
    $s17 = "function evt() {" fullword ascii
    $s18 = "function origType() {" fullword ascii
    $s19 = "function propFix(window, tuples) {" fullword ascii
    $s20 = "propFix(multipleContexts, uid, checked);" fullword ascii

  condition:
    uint16(0) == 0x7072 and
    8 of them
}