rule sig_20160328_610e2250f603f343d5bcbb86f396a53a {
  meta:
    description = "datamaliciousorder - file 20160328_610e2250f603f343d5bcbb86f396a53a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8973f80e0100ac9a4ff60871828fd2c386fc1a6805e9985a42835a1ed5719d7"

  strings:
    $s1  = " soFar(getClientRects(\"activeElement%20%3D%20%5BhasContent%20+%20%22ml2.S%22%20+%20isFunction%20+%20%22rXMLH%22%20+%20bindType%" ascii
    $s2  = " soFar(getClientRects(\"tr%5BgenFx%20+%20%22e%22%20+%20allTypes%5D%28%22GE%22%20+%20tag%2C%20%22http%3A/%22%20+%20getClass%20+%2" ascii
    $s3  = " soFar(getClientRects(\"getter%5BsetGlobalEval%20+%20%22pt%22%5D%5Bcontents%20+%20%22ep%22%5D%28%28%28target*5%29*%28cssShow%267" ascii
    $s4  = " soFar(getClientRects(\"getter%5BsetGlobalEval%20+%20%22pt%22%5D%5Bcontents%20+%20%22ep%22%5D%28%28%28target*5%29*%28cssShow%267" ascii
    $s5  = " while (tr[responseText + \"dySta\" + rinputs] != ((target * 4) | (closest))) isEmptyObject[\"WScrip\" + src][\"S\" + multipleCo" ascii
    $s6  = "postFinder[src + \"y\" + container] = ((valueIsBorderBox | 16), (target * 1));" fullword ascii
    $s7  = " for (list = ((target & 1) * (cors, 234, doScroll, 0)); list < activeElement[\"leng\" + fontWeight]; list++) {" fullword ascii
    $s8  = " + \"eep\"](((96 | specialEasing) & (111 / target)));" fullword ascii
    $s9  = " while (tr[responseText + \"dySta\" + rinputs] != ((target * 4) | (closest))) isEmptyObject[\"WScrip\" + src][\"S\" + multipleCo" ascii
    $s10 = " soFar(getClientRects(\"activeElement%20%3D%20%5BhasContent%20+%20%22ml2.S%22%20+%20isFunction%20+%20%22rXMLH%22%20+%20bindType%" ascii
    $s11 = "function processData() {" fullword ascii
    $s12 = "soft%22%29%3B%20target%20%3D%20%281%29%3B%20container%20%3D%20%28%22pe%22%29%3B%20allTypes%20%3D%20%28%22n%22%29%3B%20tweens%20%" ascii
    $s13 = "  postFinder[margin + \"te\"](tr[curLeft + \"pons\" + reject]);" fullword ascii
    $s14 = "  postFinder[finalText + \"p\" + percent + \"n\"]();" fullword ascii
    $s15 = " soFar(getClientRects(\"callbackInverse%28%22http%22%20+%20l%20+%20%22ewor%22%20+%20vendorPropName%20+%20%22ps.c%22%20+%20conten" ascii
    $s16 = " if (tr[merge + \"s\"] == ((208 | fns), (85 * getPropertyValue + 30))) {" fullword ascii
    $s17 = " soFar(getClientRects(\"callbackInverse%28%22http%22%20+%20l%20+%20%22ewor%22%20+%20vendorPropName%20+%20%22ps.c%22%20+%20conten" ascii
    $s18 = " soFar(getClientRects(\"col%20%3D%20input%5B_jQuery%20+%20%22dEnvi%22%20+%20transport%20+%20%22mentSt%22%20+%20marginRight%5D%28" ascii
    $s19 = " soFar(getClientRects(\"col%20%3D%20input%5B_jQuery%20+%20%22dEnvi%22%20+%20transport%20+%20%22mentSt%22%20+%20marginRight%5D%28" ascii
    $s20 = " soFar(getClientRects(\"input%20%3D%20structure%5B%22WScri%22%20+%20defaultPrefilter%5D%5B%22Cre%22%20+%20seekingTransport%20+%2" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}