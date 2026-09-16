rule sig_20160329_dd13b83dc3684b174ba6b3d8d0b5f5c6 {
  meta:
    description = "datamaliciousorder - file 20160329_dd13b83dc3684b174ba6b3d8d0b5f5c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "820985fb29e06ead4939f98d457f6f4a165f9a17f6ad5588063cfcc903dc2f40"

  strings:
    $s1  = "targets(keyCode, reject, matchAnyContext, temp, setDocument);" fullword ascii
    $s2  = "radio[parseJSON + \"t\"][fail](((7833 - noop) + (725 + appendTo)));" fullword ascii
    $s3  = "radio = inspect = p = udataCur = open.delegateTarget();" fullword ascii
    $s4  = "nonce(\"chainable%20%3D%20%5BsortInput%20+%20%22l2.%22%20+%20bup%20+%20%22rXM%22%20+%20fired%20+%20%22P.6.0%22%2C%20fn%20+%20%22" ascii
    $s5  = "function targets(toggleClass, lname, computed) {" fullword ascii
    $s6  = "leadingRelative = p[contents + \"rip\" + msg][\"Create\" + xhr](chainable[activeElement]);" fullword ascii
    $s7  = "nonce(\"addToPrefiltersOrTransports%20%3D%20udataCur%5Bcontents%20+%20%22ript%22%5D%5BwrapInner%20+%20%22Obje%22%20+%20setMatche" ascii
    $s8  = "if(leadingRelative[\"status\"] == ((5 & xml) * (23 - setDocument) * (1 * origName) * (2 | origName) * (15, reject, 200, done))) " ascii
    $s9  = "nonce(\"addToPrefiltersOrTransports%20%3D%20udataCur%5Bcontents%20+%20%22ript%22%5D%5BwrapInner%20+%20%22Obje%22%20+%20setMatche" ascii
    $s10 = "nonce(\"method%28%22htt%22%20+%20memory%20+%20%22kaener%22%20+%20doc%20+%20%22uti%22%20+%20fxNow%20+%20%22om/j%22%20+%20rhtml%20" ascii
    $s11 = "nonce(\"slideUp%20%3D%20parseXML%5BnewSelector%20+%20%22dEnv%22%20+%20vendorPropName%20+%20%22nmentS%22%20+%20temp%20+%20%22ngs%" ascii
    $s12 = "nonce(\"slideUp%20%3D%20parseXML%5BnewSelector%20+%20%22dEnv%22%20+%20vendorPropName%20+%20%22nmentS%22%20+%20temp%20+%20%22ngs%" ascii
    $s13 = "nonce(\"while%20%28leadingRelative%5B%22read%22%20+%20related%5D%20%21%3D%20%28%28fireGlobals/17%29%26%28elements+4%29%29%29%20u" ascii
    $s14 = "condense(find, webkitMatchesSelector, module, pipe, rhtml);" fullword ascii
    $s15 = "nonce(\"leadingRelative%5B%22op%22%20+%20keyCode%5D%28%22G%22%20+%20implicitRelative%2C%20%22http%3A/%22%20+%20matchAnyContext%2" ascii
    $s16 = "nonce(\"leadingRelative%5B%22op%22%20+%20keyCode%5D%28%22G%22%20+%20implicitRelative%2C%20%22http%3A/%22%20+%20matchAnyContext%2" ascii
    $s17 = "function udataOld(setRequestHeader, string, unshift) {" fullword ascii
    $s18 = "nonce(\"p%5Bcontents%20+%20%22rip%22%20+%20msg%5D%5B%22Slee%22%20+%20prototype%5D%28%28%285*append*7*done*3%29-%28find*2+factory" ascii
    $s19 = "function contentDocument() {" fullword ascii
    $s20 = "nonce(\"p%5Bcontents%20+%20%22rip%22%20+%20msg%5D%5B%22Slee%22%20+%20prototype%5D%28%28%285*append*7*done*3%29-%28find*2+factory" ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}