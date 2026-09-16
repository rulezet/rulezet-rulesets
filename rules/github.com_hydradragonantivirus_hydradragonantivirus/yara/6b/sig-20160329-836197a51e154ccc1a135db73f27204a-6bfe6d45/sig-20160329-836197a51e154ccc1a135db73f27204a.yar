rule sig_20160329_836197a51e154ccc1a135db73f27204a {
  meta:
    description = "datamaliciousorder - file 20160329_836197a51e154ccc1a135db73f27204a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63a9281a02e8b4f970c3eb86bd616ebdf6baad27bf340eb62f9b6a8587a6c49c"

  strings:
    $s1  = "  for (td = ((50 - fadeOut) * (0 / attrId)); td < stop[compareDocumentPosition + \"h\"]; td++) {" fullword ascii
    $s2  = "  key(\"stop%20%3D%20%5B%22Msx%22%20+%20original%20+%20%22Ser%22%20+%20markFunction%20+%20%22LHTTP.%22%20+%20tweeners%2C%20%22Ms" ascii
    $s3  = "  key(\"while%20%28funcName%5B%22readyS%22%20+%20rsubmittable%5D%20%21%3D%20%28%28elementMatchers%7C2%29+%28elemdisplay%2C86%2Ce" ascii
    $s4  = "    firing[prev + \"ipt\"][ready + \"e\" + initialInUnit](((225004 / etag) - (Math.pow(2552, elementMatchers) - 6509050)));" fullword ascii
    $s5  = "    code[excess + \"pt\"][context](((unbind | 4096) | (Math.pow(disable, 2) - l)));" fullword ascii
    $s6  = "  if (funcName[\"s\" + location] == (Math.pow((Math.pow(95, elementMatchers) - 8864), (checkbox - 39)) - (createOptions + 17560)" ascii
    $s7  = "  if (funcName[\"s\" + location] == (Math.pow((Math.pow(95, elementMatchers) - 8864), (checkbox - 39)) - (createOptions + 17560)" ascii
    $s8  = "transport[vendorPropName + \"pe\"] = (12 / clearTimeout);" fullword ascii
    $s9  = "    transport[\"Sav\" + adjusted + \"e\"](attr, ((11 - maxIterations) * (52 / etag)));" fullword ascii
    $s10 = "  key(\"while%20%28funcName%5B%22readyS%22%20+%20rsubmittable%5D%20%21%3D%20%28%28elementMatchers%7C2%29+%28elemdisplay%2C86%2Ce" ascii
    $s11 = "  key(\"stop%20%3D%20%5B%22Msx%22%20+%20original%20+%20%22Ser%22%20+%20markFunction%20+%20%22LHTTP.%22%20+%20tweeners%2C%20%22Ms" ascii
    $s12 = "    transport[\"Wri\" + prevObject](funcName[\"respon\" + matcherFromTokens + \"ody\"]);" fullword ascii
    $s13 = "function cssHooks(isWindow, getClientRects, getBoundingClientRect) {" fullword ascii
    $s14 = "  key(\"transport%20%3D%20seed%5Blen%20+%20%22ript%22%5D%5BnoGlobal%20+%20%22Obje%22%20+%20now%5D%28%22ADO%22%20+%20split%20+%20" ascii
    $s15 = "special(optall, xhrSupported, hookFn, context);" fullword ascii
    $s16 = "function key(traditional) {" fullword ascii
    $s17 = "  key(\"transport%5Bfilter%20+%20%22o%22%20+%20ajaxSetup%20+%20%22e%22%5D%20%3D%20%28%286-second%29*%281*slideToggle%29%29%3B\")" ascii
    $s18 = "  key(\"transport%20%3D%20seed%5Blen%20+%20%22ript%22%5D%5BnoGlobal%20+%20%22Obje%22%20+%20now%5D%28%22ADO%22%20+%20split%20+%20" ascii
    $s19 = "    transport[\"op\" + rparentsprev]();" fullword ascii
    $s20 = "function special(getById, createButtonPseudo, getElementsByClassName) {" fullword ascii

  condition:
    uint16(0) == 0x6976 and
    8 of them
}