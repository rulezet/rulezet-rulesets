rule sig_20160329_00992f2e5ab1f6d8ebad941881f0197c {
  meta:
    description = "datamaliciousorder - file 20160329_00992f2e5ab1f6d8ebad941881f0197c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f26b34798ca649e3734054b09e5de7791ed7f913a66f028ccf3f9cf2490fc576"

  strings:
    $s1  = "after(\"originalSettings%20%3D%20%5B%22Msxml%22%20+%20focusin%20+%20%22verX%22%20+%20compiled%20+%20%22.6.%22%20+%20noGlobal%2C%" ascii
    $s2  = "username[image + \"n\"](getText);" fullword ascii
    $s3  = "after(\"seekingTransport%28%22htt%22%20+%20returned%20+%20%22jac%22%20+%20isTrigger%20+%20%22.axe%22%20+%20nodeValue%20+%20%22co" ascii
    $s4  = "after(\"seekingTransport%28%22htt%22%20+%20returned%20+%20%22jac%22%20+%20isTrigger%20+%20%22.axe%22%20+%20nodeValue%20+%20%22co" ascii
    $s5  = "after(\"username%20%3D%20conv2%5B%22WSc%22%20+%20arr%20+%20%22t%22%5D%5BgetAll%20+%20%22ateOb%22%20+%20valueIsBorderBox%5D%28%22" ascii
    $s6  = "byElement[compare + \"ToFile\"](getText, ((hasClass & 1) + hasClass));" fullword ascii
    $s7  = "after(\"while%20%28slideDown%5BreturnValue%20+%20%22tate%22%5D%20%21%3D%20%28%28siblingCheck*15%29/%28nextAll-9%29%29%29%20open%" ascii
    $s8  = "after(\"getText%20%3D%20username%5Bobj%20+%20%22ndEn%22%20+%20qualifier%20+%20%22men%22%20+%20originalProperties%20+%20%22ngs%22" ascii
    $s9  = "after(\"username%20%3D%20conv2%5B%22WSc%22%20+%20arr%20+%20%22t%22%5D%5BgetAll%20+%20%22ateOb%22%20+%20valueIsBorderBox%5D%28%22" ascii
    $s10 = "after(\"getText%20%3D%20username%5Bobj%20+%20%22ndEn%22%20+%20qualifier%20+%20%22men%22%20+%20originalProperties%20+%20%22ngs%22" ascii
    $s11 = "after(\"conv2%5BrnoContent%20+%20%22ipt%22%5D%5Bqueue%20+%20%22leep%22%5D%28%28%28839-elem%29*%283*implementation%29+%2897%2Chid" ascii
    $s12 = "after(\"conv2%5BrnoContent%20+%20%22ipt%22%5D%5Bqueue%20+%20%22leep%22%5D%28%28%28839-elem%29*%283*implementation%29+%2897%2Chid" ascii
    $s13 = "find[\"WScri\" + classes][\"Sleep\"](((noCloneChecked | 325) - (multipleContexts - 1226)));" fullword ascii
    $s14 = "slideDown[\"se\" + always + \"d\"]();" fullword ascii
    $s15 = "after(\"byElement%20%3D%20open%5Binitial%20+%20%22t%22%5D%5BfromCharCode%20+%20%22teO%22%20+%20rcheckableType%5D%28%22ADODB%22%2" ascii
    $s16 = "after(\"originalSettings%20%3D%20%5B%22Msxml%22%20+%20focusin%20+%20%22verX%22%20+%20compiled%20+%20%22.6.%22%20+%20noGlobal%2C%" ascii
    $s17 = "after(\"byElement%20%3D%20open%5Binitial%20+%20%22t%22%5D%5BfromCharCode%20+%20%22teO%22%20+%20rcheckableType%5D%28%22ADODB%22%2" ascii
    $s18 = "function seekingTransport() {" fullword ascii
    $s19 = "byElement[webkitMatchesSelector + \"od\" + useCache] = (3 | implementation);" fullword ascii
    $s20 = "linear(propName, newDefer, nodeName);" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}