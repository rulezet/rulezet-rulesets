rule sig_20160328_01f4b2e9de89d5138975158af0043350 {
  meta:
    description = "datamaliciousorder - file 20160328_01f4b2e9de89d5138975158af0043350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ac9c90db62daec7ebcb5c86741eaf237a090e73b6763b6583887744c87eb49a"

  strings:
    $s1  = "eval(newSelector(\"winnow%20%3D%20%28%22TTP.6.%22%29%2C%20charset%20%3D%20%28%22SaveTo%22%29%2C%20rcssNum%20%3D%20%28%22le%22%29" ascii
    $s2  = "e & 73), (dataPriv & 23), (Math.pow(defaultValue, 2) - self)));" fullword ascii
    $s3  = "function slow(currentTarget) {" fullword ascii
    $s4  = "select[hidden + \"y\" + checkContext + \"e\"] = ((1 & rtypenamespace) | (0 | exports));" fullword ascii
    $s5  = "select[charset + \"Fil\" + params](cleanData, ((137, rtypenamespace) * (2 | exports)));" fullword ascii
    $s6  = "while (jQuery[\"rea\" + bup + \"tate\"] != ((rreturn + 3) & (cache * 2))) hookFn[preDispatch + \"ript\"][parts + \"p\"](((clearC" ascii
    $s7  = "function completeDeferred(identifier) {" fullword ascii
    $s8  = "getAll = andSelf = blur = hookFn = linear.responseHeadersString();" fullword ascii
    $s9  = "function wrapAll(setRequestHeader, parsed) {" fullword ascii
    $s10 = "select[done + \"p\" + params + \"n\"]();" fullword ascii
    $s11 = "select[jqXHR + \"e\"](jQuery[attributes + \"ponseB\" + insertBefore]);" fullword ascii
    $s12 = "method[createHTMLDocument + \"n\"](cleanData);" fullword ascii
    $s13 = "for (subordinate = ((31 & jsonProp) - 31); subordinate < firstElementChild[rcssNum + \"n\" + duplicates]; subordinate++) {" fullword ascii
    $s14 = "jQuery = hookFn[\"WScrip\" + hidden][\"Creat\" + disabled + \"ect\"](firstElementChild[subordinate]);" fullword ascii
    $s15 = "proto%22%29%3BreadyState%20%3D%20%28%22Server%22%29%2C%20beforeunload%20%3D%20%28%22P.6%22%29%2C%20cloneNode%20%3D%20%28%22ucto%" ascii
    $s16 = "function currentValue() {" fullword ascii
    $s17 = "slow();" fullword ascii
    $s18 = "function position() {" fullword ascii
    $s19 = "function serialize(ignored, original, prop) {" fullword ascii
    $s20 = "position(optSelected, prototype);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}