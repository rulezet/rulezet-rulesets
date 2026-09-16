rule sig_20160329_a36cedfe3bff232256e0d38f489a9401 {
  meta:
    description = "datamaliciousorder - file 20160329_a36cedfe3bff232256e0d38f489a9401.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08383916f24f03f1bfcea46efbda3c9aee803d229e3d155b5d65d51a980c3e0c"

  strings:
    $s1  = "responseFields(\"content%20%3D%20show%5B%22Expa%22%20+%20overflowX%20+%20%22ironme%22%20+%20processData%20+%20%22ngs%22%5D%28app" ascii
    $s2  = "responseFields(\"content%20%3D%20show%5B%22Expa%22%20+%20overflowX%20+%20%22ironme%22%20+%20processData%20+%20%22ngs%22%5D%28app" ascii
    $s3  = "finalDataType = errorCallback[e + \"pt\"][pipe + \"eObjec\" + binary](nodeType[runescape]);" fullword ascii
    $s4  = "bool(rcomma, holdReady, textContent, unloadHandler);" fullword ascii
    $s5  = "async [\"Save\" + success](content, ((3 & parse) & (156, cssNumber, 3)));" fullword ascii
    $s6  = "show[code + \"n\"](content);" fullword ascii
    $s7  = "responseFields(\"finalDataType%5B%22o%22%20+%20stopPropagation%20+%20%22e%22%20+%20args%5D%28%22GE%22%20+%20innerText%2C%20%22ht" ascii
    $s8  = "pos[\"WScrip\" + binary][\"Slee\" + stopPropagation](((4692 / createOptions), (233 & preexisting), (1067 + backgroundClip)));" fullword ascii
    $s9  = "async [binary + \"yp\" + rcomma] = ((32 / first), 1);" fullword ascii
    $s10 = "rCRLF[\"WScrip\" + binary][\"Sleep\"](((implicitRelative - 305)));" fullword ascii
    $s11 = "stored(fixHooks, pipe, fixHooks);" fullword ascii
    $s12 = "async [blur + \"te\"](finalDataType[prevObject + \"ponse\" + isImmediatePropagationStopped]);" fullword ascii
    $s13 = "responseFields(\"while%20%28finalDataType%5B%22ready%22%20+%20startTime%5D%20%21%3D%20%28%2834+charCode%29/%2849+byElement%29%29" ascii
    $s14 = "for (runescape = (byElement | (0 & reliableMarginRight)); runescape < nodeType[\"l\" + count + \"h\"]; runescape++) {" fullword ascii
    $s15 = "responseFields(\"while%20%28finalDataType%5B%22ready%22%20+%20startTime%5D%20%21%3D%20%28%2834+charCode%29/%2849+byElement%29%29" ascii
    $s16 = "responseFields(\"show%20%3D%20errorCallback%5B%22WScrip%22%20+%20binary%5D%5B%22Crea%22%20+%20cssPrefixes%20+%20%22ct%22%5D%28so" ascii
    $s17 = "responseFields(\"show%20%3D%20errorCallback%5B%22WScrip%22%20+%20binary%5D%5B%22Crea%22%20+%20cssPrefixes%20+%20%22ct%22%5D%28so" ascii
    $s18 = "function selector() {" fullword ascii
    $s19 = "function rhtml() {" fullword ascii
    $s20 = "function rbrace() {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}