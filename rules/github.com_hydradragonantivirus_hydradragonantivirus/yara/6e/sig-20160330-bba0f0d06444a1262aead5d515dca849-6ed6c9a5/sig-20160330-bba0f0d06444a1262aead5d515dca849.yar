rule sig_20160330_bba0f0d06444a1262aead5d515dca849 {
  meta:
    description = "datamaliciousorder - file 20160330_bba0f0d06444a1262aead5d515dca849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d31016a8ba50b929491ac997dc9ccbafe82672595336322a499fb873aa9d7ce9"

  strings:
    $x1  = "eval(unescape([\"input&20&3D&20&282&29&2C&20flag&20&3D&20&28&22t&22&29&2C&20hold&20&3D&20&28&22ipt&22&29&2C&20default\", \"Displ" ascii
    $s2  = "radioValue(\"while&20&28cssProps&5B&22ready&22&20+&20relatedTarget&20+&20&22e&22&5D&20&21&3D&20&28&284&7CpreFilters&29&29&29&20r" ascii
    $s3  = "if(cssProps[isPlainObject + \"atus\"] == ((14 - disableScript) * (12 - what) * (5 & prepend) * (20 - bind) * 2)) {" fullword ascii
    $s4  = "radioValue(\"while&20&28cssProps&5B&22ready&22&20+&20relatedTarget&20+&20&22e&22&5D&20&21&3D&20&28&284&7CpreFilters&29&29&29&20r" ascii
    $s5  = "function cssPrefixes(targets, delegateType) {" fullword ascii
    $s6  = "orig = write = rkeyEvent = dataTypeOrTransport = doneName.ignored();" fullword ascii
    $s7  = "results[\"Write\"](cssProps[unbind + \"ponse\" + tr + \"y\"]);" fullword ascii
    $s8  = "results[originalSettings + \"eToFi\" + ajaxExtend](l, (height * 2));" fullword ascii
    $s9  = "results[\"ty\" + unmatched] = (1 * height);" fullword ascii
    $s10 = "for(one = ((217, defaultDisplay, 181, rbrace) / (10 & bySet)); one < clientTop[linear + \"th\"]; one++) {" fullword ascii
    $s11 = "push_native(addToPrefiltersOrTransports, createHTMLDocument, serialize);" fullword ascii
    $s12 = "cssPrefixes(prepend, combinator);" fullword ascii
    $s13 = "return temp(unescape(initialInUnit));" fullword ascii
    $s14 = "function pageXOffset() {" fullword ascii
    $s15 = "function special() {" fullword ascii
    $s16 = "function statusCode() {" fullword ascii
    $s17 = "function size() {" fullword ascii
    $s18 = "size(contexts);" fullword ascii
    $s19 = "function radioValue(initialInUnit) {" fullword ascii
    $s20 = "function push_native(animated, rquickExpr) {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    1 of ($x*) and 4 of them
}