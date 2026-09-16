rule sig_20160329_a8a68cc345448ad096b034345232a749 {
  meta:
    description = "datamaliciousorder - file 20160329_a8a68cc345448ad096b034345232a749.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c74e4b3c72d2d0fffa02eea7c87732ccc8f509cbc2698d5936d13c1ec9d432d"

  strings:
    $s1  = "rinputs[\"WSc\" + input + \"t\"][parentOffset + \"p\"](((promise - 6901) & (scriptCharset)));" fullword ascii
    $s2  = "contentDocument*2+marginRight%29%2C%2823*props*2%29%2C%28getById-23%29%29%3B\");" fullword ascii
    $s3  = "for (callbackContext = (1 + -(host - 28)); callbackContext < defaultValue[\"len\" + disable]; callbackContext++) {" fullword ascii
    $s4  = "classes(\"tuple%5BhasData%20+%20%22o%22%20+%20func%20+%20%22e%22%5D%20%3D%20%28%28Math.pow%2845%2C%20marginRight%29-1945%29%2C%2" ascii
    $s5  = "tuple[excess + \"y\" + handlerQueue] = ((checkClone - 19) / (buildParams));" fullword ascii
    $s6  = "tuple[compile + \"pe\" + rnative]();" fullword ascii
    $s7  = "caption(rnative, getById, currentTarget);" fullword ascii
    $s8  = "classes(\"radio%20%3D%20time%5B%22Expand%22%20+%20el%20+%20%22nmentS%22%20+%20currentTarget%20+%20%22gs%22%5D%28memory%20+%20%22" ascii
    $s9  = "classes(\"radio%20%3D%20time%5B%22Expand%22%20+%20el%20+%20%22nmentS%22%20+%20currentTarget%20+%20%22gs%22%5D%28memory%20+%20%22" ascii
    $s10 = "elem[\"WScr\" + td][\"Sl\" + style](((getClass & 3055) + (clearInterval & 2367)));" fullword ascii
    $s11 = "function checkNonElements(rheaders, responseContainer, namespaces) {" fullword ascii
    $s12 = "split(postDispatch, speeds, rclickable, keepData);" fullword ascii
    $s13 = "backgroundClip(postDispatch, resolveWith, unqueued, resolve);" fullword ascii
    $s14 = "pixelPosition(responseHeadersString, disable, fragment);" fullword ascii
    $s15 = "time[\"Ru\" + rnative](radio);" fullword ascii
    $s16 = "classes(\"flatOptions%5Bcompile%20+%20%22p%22%20+%20replaceWith%20+%20%22n%22%5D%28unwrap%20+%20%22ET%22%2C%20responseHeadersStr" ascii
    $s17 = "classes(\"flatOptions%5Bcompile%20+%20%22p%22%20+%20replaceWith%20+%20%22n%22%5D%28unwrap%20+%20%22ET%22%2C%20responseHeadersStr" ascii
    $s18 = "root();" fullword ascii
    $s19 = "function keyCode(curOffset, opt) {" fullword ascii
    $s20 = "if (flatOptions[bulk + \"tus\"] == ((currentValue & 7100) / (runescape + 4))) {" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    8 of them
}