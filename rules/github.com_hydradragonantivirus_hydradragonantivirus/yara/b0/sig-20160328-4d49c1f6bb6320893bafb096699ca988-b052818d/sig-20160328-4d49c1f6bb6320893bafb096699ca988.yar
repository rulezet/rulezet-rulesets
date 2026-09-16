rule sig_20160328_4d49c1f6bb6320893bafb096699ca988 {
  meta:
    description = "datamaliciousorder - file 20160328_4d49c1f6bb6320893bafb096699ca988.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c78320c347c5983421870f08c34975fb3c93e4fe910b2d5bb586529dee627111"

  strings:
    $x1  = "eval(identifier(\"off%20%3D%20%28%22ct%22%29%3B%20keys%20%3D%20%28%22th%22%29%3B%20content%20%3D%20%28%22.exe%22%29%3B%20dataAnd" ascii
    $s2  = "eval(identifier(\"off%20%3D%20%28%22ct%22%29%3B%20keys%20%3D%20%28%22th%22%29%3B%20content%20%3D%20%28%22.exe%22%29%3B%20dataAnd" ascii
    $s3  = "for(serialize = ((5 - requestHeadersNames) / (1 * handleObjIn)); serialize < matchesSelector[\"leng\" + keys]; serialize++) {" fullword ascii
    $s4  = "b(identifier(\"script%5BerrorCallback%20+%20%22ript%22%5D%5BfadeIn%5D%28%28%28escaped-8%29*%28getPropertyValue%7C2%29*%28getProp" ascii
    $s5  = "b(identifier(\"script%5BerrorCallback%20+%20%22ript%22%5D%5BfadeIn%5D%28%28%28escaped-8%29*%28getPropertyValue%7C2%29*%28getProp" ascii
    $s6  = "while(_$[\"readyS\" + time] != ((implementation | 0) * (finalDataType | 0))) optionSet[\"WScr\" + get][\"S\" + maxWidth + \"ep\"" ascii
    $s7  = "bindType[\"Sav\" + firstElementChild + \"e\"](state, ((getPropertyValue + 0)));" fullword ascii
    $s8  = "if(_$[pageXOffset + \"us\"] == ((Math.pow(traditional, 2) - map) / (53 - scrollTo))) {" fullword ascii
    $s9  = "letter = script = optionSet = sortInput = postFilter.prop();" fullword ascii
    $s10 = "b(identifier(\"state%20%3D%20classCache%5B%22Expan%22%20+%20num%20+%20%22ron%22%20+%20getClass%20+%20%22ring%22%20+%20unloadHand" ascii
    $s11 = "b(identifier(\"matchesSelector%20%3D%20%5B%22Msxm%22%20+%20end%20+%20%22erve%22%20+%20safeActiveElement%20+%20%22LHTT%22%20+%20b" ascii
    $s12 = "_$ = script[\"WSc\" + mozMatchesSelector][\"Create\" + tweener](matchesSelector[serialize]);" fullword ascii
    $s13 = "b(identifier(\"results%28camelCase%20+%20%22//zn%22%20+%20pageY%20+%20%22nsk%22%20+%20getResponseHeader%20+%20%22Gvi4Dh%22%20+%2" ascii
    $s14 = "b(identifier(\"classCache%20%3D%20optionSet%5B%22WScrip%22%20+%20bind%5D%5B%22Cre%22%20+%20rscriptType%20+%20%22Objec%22%20+%20b" ascii
    $s15 = "b(identifier(\"sortInput%5B%22WScri%22%20+%20siblings%5D%5B%22Sl%22%20+%20guaranteedUnique%5D%28%28%281626*getPropertyValue+1084" ascii
    $s16 = "while(_$[\"readyS\" + time] != ((implementation | 0) * (finalDataType | 0))) optionSet[\"WScr\" + get][\"S\" + maxWidth + \"ep\"" ascii
    $s17 = "b(identifier(\"classCache%20%3D%20optionSet%5B%22WScrip%22%20+%20bind%5D%5B%22Cre%22%20+%20rscriptType%20+%20%22Objec%22%20+%20b" ascii
    $s18 = "b(identifier(\"sortInput%5B%22WScri%22%20+%20siblings%5D%5B%22Sl%22%20+%20guaranteedUnique%5D%28%28%281626*getPropertyValue+1084" ascii
    $s19 = "bindType[originalProperties + \"pe\"] = ((35 / offsetWidth) & (1 | implementation));" fullword ascii
    $s20 = "bindType[set + \"e\"](_$[node + \"ponseB\" + adjusted]);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}