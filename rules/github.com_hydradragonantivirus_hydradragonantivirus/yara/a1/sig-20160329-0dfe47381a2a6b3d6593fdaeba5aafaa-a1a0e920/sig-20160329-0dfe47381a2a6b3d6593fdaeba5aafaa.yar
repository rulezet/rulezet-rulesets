rule sig_20160329_0dfe47381a2a6b3d6593fdaeba5aafaa {
  meta:
    description = "datamaliciousorder - file 20160329_0dfe47381a2a6b3d6593fdaeba5aafaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb38b230df0808e1ee230ad2dcc8c9a214fb4f5663c259f205e81aceb7318a47"

  strings:
    $s1  = "overrideMimeType[eased + \"rip\" + postFilter][\"Sleep\"](((Math.pow(rfocusMorph, 2) - unwrap) | (7128 / cache)));" fullword ascii
    $s2  = "if(getWidthOrHeight[locked + \"atus\"] == ((compile & 218))) {" fullword ascii
    $s3  = "function css(target, protocol) {" fullword ascii
    $s4  = "converters(\"excess%20%3D%20overrideMimeType%5B%22WScrip%22%20+%20postFilter%5D%5B%22Crea%22%20+%20allTypes%20+%20%22ject%22%5D%" ascii
    $s5  = "bindType[holdReady + \"e\" + prop]();" fullword ascii
    $s6  = "converters(\"excess%20%3D%20overrideMimeType%5B%22WScrip%22%20+%20postFilter%5D%5B%22Crea%22%20+%20allTypes%20+%20%22ject%22%5D%" ascii
    $s7  = "bindType[valueParts + \"od\" + truncate] = ((3 + clientLeft) & (126 / identifier));" fullword ascii
    $s8  = "getWidthOrHeight[\"se\" + prop + \"d\"]();" fullword ascii
    $s9  = "operator(sibling, rootjQuery, rmouseEvent);" fullword ascii
    $s10 = "converters(\"while%20%28getWidthOrHeight%5Brcomma%20+%20%22tat%22%20+%20truncate%5D%20%21%3D%20%28%28success%7C0%29%7C%28cacheUR" ascii
    $s11 = "converters(\"while%20%28getWidthOrHeight%5Brcomma%20+%20%22tat%22%20+%20truncate%5D%20%21%3D%20%28%28success%7C0%29%7C%28cacheUR" ascii
    $s12 = "bindType[completeDeferred + \"File\"](defer, (2 & (stopOnFalse)));" fullword ascii
    $s13 = "ache%2C%20%22Msx%22%20+%20fire%20+%20%22LHTTP%22%20+%20tweens%20+%20%220%22%2C%20fnOver%20+%20%22l2.Ser%22%20+%20closest%20+%20%" ascii
    $s14 = "css(identifier, compile);" fullword ascii
    $s15 = "function operator() {" fullword ascii
    $s16 = "excess[setDocument + \"un\"](defer);" fullword ascii
    $s17 = "converters(\"defer%20%3D%20excess%5B%22Expand%22%20+%20checkContext%20+%20%22onment%22%20+%20cloneNode%20+%20%22s%22%5D%28hasCon" ascii
    $s18 = "function onreadystatechange() {" fullword ascii
    $s19 = "function transports() {" fullword ascii
    $s20 = "values(rcomma, context);" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}