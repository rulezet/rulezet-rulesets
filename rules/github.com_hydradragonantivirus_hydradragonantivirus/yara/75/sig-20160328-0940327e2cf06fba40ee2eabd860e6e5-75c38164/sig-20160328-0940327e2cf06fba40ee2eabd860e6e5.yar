rule sig_20160328_0940327e2cf06fba40ee2eabd860e6e5 {
  meta:
    description = "datamaliciousorder - file 20160328_0940327e2cf06fba40ee2eabd860e6e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44335def889ed4d3e1be0f1fb8cc2155bcc03deec04177c5fe45362a9f54f912"

  strings:
    $s1  = "   while(support[abort + \"yState\"] != (Math.pow((qsaError), (2 & isEmptyObject)) - (175 / time))) serializeArray[result + \"t" ascii
    $s2  = "   while(support[abort + \"yState\"] != (Math.pow((qsaError), (2 & isEmptyObject)) - (175 / time))) serializeArray[result + \"t" ascii
    $s3  = "soFar[\"ty\" + dirrunsUnique + \"e\"] = (1 | keys);" fullword ascii
    $s4  = "      soFar[removeEventListener + \"oFile\"](rhash, ((callbackInverse / 28), (pattern / 20), (getBoundingClientRect, 205, rident" ascii
    $s5  = "         support = special[\"WScrip\" + _$][\"Crea\" + matchContext + \"ct\"](getComputedStyle[load]);" fullword ascii
    $s6  = "soFar[udataOld + \"od\" + nodeValue] = ((1 & keys) * (3 & qsaError));" fullword ascii
    $s7  = "   for(load = 0; load < getComputedStyle[\"lengt\" + isHidden]; load++) {" fullword ascii
    $s8  = "      soFar[removeEventListener + \"oFile\"](rhash, ((callbackInverse / 28), (pattern / 20), (getBoundingClientRect, 205, rident" ascii
    $s9  = "progressValues(nodeValue, pattern, getElementsByName, childNodes);" fullword ascii
    $s10 = "special = valueIsBorderBox = serializeArray = rheaders = seed.clientLeft();" fullword ascii
    $s11 = "function onreadystatechange(cloneNode) {" fullword ascii
    $s12 = "register(ridentifier, childNodes, unwrap, position, curCSSLeft);" fullword ascii
    $s13 = "function attrHandle(code, username) {" fullword ascii
    $s14 = "function rnumnonpx(responses, idx, bindType) {" fullword ascii
    $s15 = "         support[container + \"e\" + global + \"d\"]();" fullword ascii
    $s16 = "   if(support[ofType + \"atu\" + container] == ((async / 16), (udataCur | 72))) {" fullword ascii
    $s17 = "function cos(set, rreturn) {" fullword ascii
    $s18 = "function attributes(Sizzle) {" fullword ascii
    $s19 = "function progressValues(replaceAll, _evalUrl) {" fullword ascii
    $s20 = "function register(lname, wrapAll, oldfire) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}