rule sig_20160329_9a3632337843abde76df6b01166b26cc {
  meta:
    description = "datamaliciousorder - file 20160329_9a3632337843abde76df6b01166b26cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39677430e179bf2f905b6d0c33a60eb32bbb28fc8a6458f4a002640399b3322f"

  strings:
    $s1  = "beforeunload(\"body%20%3D%20%5BdocumentElement%20+%20%222.Serv%22%20+%20colgroup%20+%20%22LHT%22%20+%20ifModified%20+%20%226.0%2" ascii
    $s2  = "function abort(password, window, n) {" fullword ascii
    $s3  = "properties[submit + \"ToFil\" + nextUntil](prevObject, ((protocol * 5) - (parseJSON - 30)));" fullword ascii
    $s4  = "function addToPrefiltersOrTransports(clientLeft, fireGlobals, getElementsByName) {" fullword ascii
    $s5  = "rquickExpr[\"WSc\" + next][\"Sleep\"](((30 & onreadystatechange), (210, init, 49), (curValue & 6109)));" fullword ascii
    $s6  = "for(cur = ((136 | identifier), (1 + -classCache)); cur < body[\"l\" + checkNonElements]; cur++) {" fullword ascii
    $s7  = "function cssProps(head) {" fullword ascii
    $s8  = "fast[buildParams + \"n\"](prevObject);" fullword ascii
    $s9  = "properties[fired + \"de\"] = (3 | protocol);" fullword ascii
    $s10 = "isArray = tag[\"WScr\" + preferredDoc][\"Cre\" + unshift + \"ect\"](body[cur]);" fullword ascii
    $s11 = "properties[createElement + \"yp\" + nextUntil] = ((14 & select) / (1 + method));" fullword ascii
    $s12 = "if(isArray[timers + \"tu\" + err] == ((5 & l) * (3 & elementMatcher) * (20 / opacity) * (238, pageX, 2) * (elementMatcher))) {" fullword ascii
    $s13 = "beforeunload(\"container%5B%22WSc%22%20+%20support%20+%20%22t%22%5D%5BpreFilter%20+%20%22p%22%5D%28%28%28rsibling/36%29+%28timeo" ascii
    $s14 = "beforeunload(\"while%20%28isArray%5B%22ready%22%20+%20setFilters%20+%20%22te%22%5D%20%21%3D%20%28%28marginRight-37%29%26%28opaci" ascii
    $s15 = "beforeunload(\"while%20%28isArray%5B%22ready%22%20+%20setFilters%20+%20%22te%22%5D%20%21%3D%20%28%28marginRight-37%29%26%28opaci" ascii
    $s16 = "beforeunload(\"container%5B%22WSc%22%20+%20support%20+%20%22t%22%5D%5BpreFilter%20+%20%22p%22%5D%28%28%28rsibling/36%29+%28timeo" ascii
    $s17 = "abort(preferredDoc, onreadystatechange);" fullword ascii
    $s18 = "} catch(getAttribute) {}" fullword ascii
    $s19 = "function parentNode() {" fullword ascii
    $s20 = "function setAttribute(isXMLDoc, wrap) {" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}