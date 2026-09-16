rule sig_20160311_40d047d404b307c06643ac32e6ba39ab {
  meta:
    description = "datamaliciousorder - file 20160311_40d047d404b307c06643ac32e6ba39ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f941147c31db242dc53ac7e49a3d585b96fa10a3aa81dac8232f152e361dac6"

  strings:
    $s1  = "args[\"op\".statusText() + offsetHeight](\"G\" + b, \"http:/\" + elements + \"gov.sd\".statusText() + elemLang + \"r35y4\" + sel" ascii
    $s2  = "finalDataType[factory + \"n\".statusText()](_data.statusText((Math.pow((body * 3 + win), (2 + scripts)) - (5874 - border))), ((1" ascii
    $s3  = "((((stopped & (1 & stopped)) + (1 * (scripts | 1))) & ((scripts | 1) * (attrHooks, 3))) | ((((Math.pow(cache, 2) - arr) / (11 * " ascii
    $s4  = "win - 3)) - (promise & 59356)), ((delegateType | 137), (rsingleTag / 1), (head & 7)))))));" fullword ascii
    $s5  = "finalDataType[factory + \"n\".statusText()](_data.statusText((Math.pow((body * 3 + win), (2 + scripts)) - (5874 - border))), ((1" ascii
    $s6  = "args = matchedCount[\"WScr\" + prevUntil][\"Create\".statusText() + writable + \"ect\"](getElementsByTagName + \"L2.XML\" + size" ascii
    $s7  = "matchedCount = (((Math.pow(553, xhrSuccessStatus) - 304709) / xhrSuccessStatus * 5 * win), ((192 - undelegate), (15 & finish)), " ascii
    $s8  = "function processData() {" fullword ascii
    $s9  = "matchedCount = (((Math.pow(553, xhrSuccessStatus) - 304709) / xhrSuccessStatus * 5 * win), ((192 - undelegate), (15 & finish)), " ascii
    $s10 = "xhrSuccessStatus)), ((93 - rcheckableType) * (Math.pow(3, xhrSuccessStatus) - 5) + (useCache / 30)), (Math.pow((sibling / 35), (" ascii
    $s11 = "args[\"op\".statusText() + offsetHeight](\"G\" + b, \"http:/\" + elements + \"gov.sd\".statusText() + elemLang + \"r35y4\" + sel" ascii
    $s12 = "isReady = stopOnFalse[value + \"teObj\" + curElem](\"WScri\".statusText() + done + \"Shel\" + tr);" fullword ascii
    $s13 = "head = 7;" fullword ascii
    $s14 = "t()) + index + \".s\" + createFxNow;" fullword ascii
    $s15 = "rlocalProtocol[\"sav\" + defaultValue + \"ile\"](_data, (stopped * 2));" fullword ascii
    $s16 = "_data = isReady[\"Exp\" + addClass + \"Envi\".statusText() + callbackInverse + \"ntSt\" + MAX_NEGATIVE + \"gs\"](rCRLF + \"P%/\"" ascii
    $s17 = "border = 2482, finish = 14, size = \"HTTP\", fireGlobals = \"onse\", rsingleTag = 233, factory = \"Ru\";" fullword ascii
    $s18 = "return optgroup" fullword ascii
    $s19 = "function v() {" fullword ascii
    $s20 = "function dataAttr() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}