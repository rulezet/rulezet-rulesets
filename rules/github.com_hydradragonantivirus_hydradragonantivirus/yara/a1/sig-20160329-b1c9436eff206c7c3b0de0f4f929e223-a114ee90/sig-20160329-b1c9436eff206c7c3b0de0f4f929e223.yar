rule sig_20160329_b1c9436eff206c7c3b0de0f4f929e223 {
  meta:
    description = "datamaliciousorder - file 20160329_b1c9436eff206c7c3b0de0f4f929e223.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "372367cefb5d52ac5eb4b606a68a55322fd794c5642b63d3a7e3c7b45f4a32ae"

  strings:
    $s1  = "filter(\"while%20%28isPropagationStopped%5BoptionSet%20+%20%22Sta%22%20+%20dataTypeOrTransport%5D%20%21%3D%20%28%28rmouseEvent+2" ascii
    $s2  = "filter(\"len%20%3D%20%5B%22Msx%22%20+%20event%20+%20%22erver%22%20+%20headers%20+%20%22TTP.6%22%20+%20converters%2C%20%22Msxml%2" ascii
    $s3  = "function stopOnFalse(namespace, manipulationTarget, matched) {" fullword ascii
    $s4  = "filter(\"isPropagationStopped%5BtimeoutTimer%20+%20%22pe%22%20+%20cssFn%5D%28%22GE%22%20+%20configurable%2C%20%22htt%22%20+%20to" ascii
    $s5  = "rnamespace(radioValue, headers, hash);" fullword ascii
    $s6  = "filter(\"subordinate%20%3D%20fromCharCode%5B%22WScr%22%20+%20el%5D%5B%22Create%22%20+%20tmp%20+%20%22ct%22%5D%28isNumeric%20+%20" ascii
    $s7  = "filter(\"attaches%28checked%20+%20%22//c%22%20+%20fnOver%20+%20%22etord%22%20+%20reset%20+%20%22ade.co%22%20+%20disable%20+%20%2" ascii
    $s8  = "filter(\"fromCharCode%5BrequestHeaders%20+%20%22ript%22%5D%5Btbody%20+%20%22ep%22%5D%28%28%28720*unique+249%29*%28createPseudo*2" ascii
    $s9  = "filter(\"len%20%3D%20%5B%22Msx%22%20+%20event%20+%20%22erver%22%20+%20headers%20+%20%22TTP.6%22%20+%20converters%2C%20%22Msxml%2" ascii
    $s10 = "filter(\"fromCharCode%5BrequestHeaders%20+%20%22ript%22%5D%5Btbody%20+%20%22ep%22%5D%28%28%28720*unique+249%29*%28createPseudo*2" ascii
    $s11 = "indirect = unquoted = values = fromCharCode = fadeTo.contentDocument();" fullword ascii
    $s12 = "test(disable, globalEval, overflowX, postSelector);" fullword ascii
    $s13 = "subordinate[timeoutTimer + \"pe\" + cssFn]();" fullword ascii
    $s14 = "subordinate[\"Write\"](isPropagationStopped[rmultiDash + \"onse\" + type + \"y\"]);" fullword ascii
    $s15 = "subordinate[\"ty\" + returned + \"e\"] = (createPseudo + 0);" fullword ascii
    $s16 = "indirect[b + \"t\"][adown + \"p\"](((67026 + promise) / (30 | rinputs)));" fullword ascii
    $s17 = "noop[clazz + \"un\"](append);" fullword ascii
    $s18 = "subordinate[constructor + \"File\"](append, (2 | (rfxtypes)));" fullword ascii
    $s19 = "filter(\"while%20%28isPropagationStopped%5BoptionSet%20+%20%22Sta%22%20+%20dataTypeOrTransport%5D%20%21%3D%20%28%28rmouseEvent+2" ascii
    $s20 = "stopOnFalse(first, raw, dirruns);" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}