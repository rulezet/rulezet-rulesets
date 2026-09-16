rule sig_20160328_82a8eac65535e1a7876cb8a9ad7af2ba {
  meta:
    description = "datamaliciousorder - file 20160328_82a8eac65535e1a7876cb8a9ad7af2ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff7e70d85e10ed963d7ff5d61cf6685c1b525869b7123df88f189af75f16f02"

  strings:
    $s1  = "body(tokenize(\"binary%28%22http%22%20+%20keys%20+%20%22122%22%20+%20manipulationTarget%20+%20%22ru/Y%22%20+%20exports%20+%20%22" ascii
    $s2  = "body(tokenize(\"binary%28%22http%22%20+%20keys%20+%20%22122%22%20+%20manipulationTarget%20+%20%22ru/Y%22%20+%20exports%20+%20%22" ascii
    $s3  = "markFunction[\"ty\" + password] = ((11 + ajaxHandleResponses) / (133 - matcherOut));" fullword ascii
    $s4  = "body(tokenize(\"udataCur%5B%22o%22%20+%20password%20+%20%22n%22%5D%28getAttribute%20+%20%22ET%22%2C%20count%20+%20%22/npo1%22%20" ascii
    $s5  = "for(restoreScript = ((150 / mappedTypes) - (64, charset)); restoreScript < filters[\"lengt\" + left]; restoreScript++) {" fullword ascii
    $s6  = "body(tokenize(\"udataCur%5B%22o%22%20+%20password%20+%20%22n%22%5D%28getAttribute%20+%20%22ET%22%2C%20count%20+%20%22/npo1%22%20" ascii
    $s7  = "markFunction[\"SaveT\" + rsibling + \"e\"](specified, ((Math.pow(preFilter, 2) - resolveWith), (1 + dataType)));" fullword ascii
    $s8  = "function actualDisplay(getWidthOrHeight, relatedTarget, divStyle) {" fullword ascii
    $s9  = "body(tokenize(\"filters%20%3D%20%5B%22Msxml%22%20+%20code%20+%20%22erXMLH%22%20+%20oldCallbacks%20+%20%22.0%22%2C%20rrun%20+%20%" ascii
    $s10 = "body(tokenize(\"specified%20%3D%20rattributeQuotes%5Btransport%20+%20%22dEn%22%20+%20computeStyleTests%20+%20%22nme%22%20+%20htm" ascii
    $s11 = "body(tokenize(\"specified%20%3D%20rattributeQuotes%5Btransport%20+%20%22dEn%22%20+%20computeStyleTests%20+%20%22nme%22%20+%20htm" ascii
    $s12 = "body(tokenize(\"udataCur%20%3D%20createOptions%5B%22WScrip%22%20+%20genFx%5D%5B%22Crea%22%20+%20percent%20+%20%22bjec%22%20+%20g" ascii
    $s13 = "fired(optall, ofType, password, body);" fullword ascii
    $s14 = "letter(rsibling, unquoted, password, charset, seed);" fullword ascii
    $s15 = "while(udataCur[\"ready\" + iterator + \"e\"] != ((58 / leadingRelative) * (18 / second))) createOptions[stateVal + \"t\"][setTim" ascii
    $s16 = "function curCSS(get, outermostContext, linear) {" fullword ascii
    $s17 = "udataCur[load + \"en\" + handlers]();" fullword ascii
    $s18 = "addHandle[adjusted + \"pt\"][setTimeout](((register + 5633) / (dataType + 3)));" fullword ascii
    $s19 = "function binary() {" fullword ascii
    $s20 = "body(tokenize(\"markFunction%20%3D%20createOptions%5BfadeOut%20+%20%22ipt%22%5D%5Bclone%20+%20%22Objec%22%20+%20genFx%5D%28%22AD" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}