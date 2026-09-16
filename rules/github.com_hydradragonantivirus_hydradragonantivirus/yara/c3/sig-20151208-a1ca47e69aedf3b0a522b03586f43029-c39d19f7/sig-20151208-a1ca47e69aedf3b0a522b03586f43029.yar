rule sig_20151208_a1ca47e69aedf3b0a522b03586f43029 {
  meta:
    description = "datamaliciousorder - file 20151208_a1ca47e69aedf3b0a522b03586f43029.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c9561d7df19092a8026462532b8ceaa7322d4e3bd8ef341afa4f2661e1a2ea5"

  strings:
    $s1  = "function fpYzVAlWAfidRXOwGFBjlQHkDGcbKRwIRqKKUhTSYqFPhmVRJHDLWR(uCuIdZnqSdNsD,PCWfrjQAaqYvSQ){ return CsBXIhSlECrBQ[kmOsL(uCuIdZ" ascii
    $s2  = "push(\"98\");c.push(\"114\");c.push(\"101\");c.push(\"97\");c.push(\"107\");c.push(\"59\");c.push(\"13\");c.push(\"10\");c.push(" ascii
    $s3  = "JkCXW)}function kmOsL(zxAdfOrJjXG,zupfyRErUtBJn,wgeCMZaf){bjOk=parseInt(zxAdfOrJjXG,zupfyRErUtBJn);mNhXl=bjOk.toString(wgeCMZaf)" ascii
    $s4  = "function uAUiwLEWpUv(ZXZuBybq,QiSDBV){return ZXZuBybq.split(QiSDBV)}" fullword ascii
    $s5  = "push(\"59\");c.push(\"32\");c.push(\"13\");c.push(\"10\");c.push(\"9\");c.push(\"9\");c.push(\"32\");c.push(\"32\");c.push(\"32" ascii
    $s6  = ";return mNhXl;}function QedIqBwlHCzEDAr(uhxTsWmRWgERnDBSH){eval(uhxTsWmRWgERnDBSH)}" fullword ascii
    $s7  = "push(\"87\");H.push(\"83\");H.push(\"99\");H.push(\"114\");H.push(\"105\");H.push(\"34\");H.push(\"58\");H.push(\"34\");H.push(" ascii
    $s8  = "}} return DyvRlUXGNzC}" fullword ascii
    $s9  = "LaqUyYoRW[iKvflpJxoQY]=(-403+403)/895; while(true) { if(LaqUyYoRW[iKvflpJxoQY] > pUXNQ[iKvflpJxoQY].length-(32+69)/101) { break;" ascii
    $s10 = "function pJkIOJjkVIVpqchpm(pUXNQ){DyvRlUXGNzC= '';for(iKvflpJxoQY=(-745+745)/689; iKvflpJxoQY < (-792+992)/100; iKvflpJxoQY++) {" ascii
    $s11 = "push(\"13\");c.push(\"10\");" fullword ascii
    $s12 = "push(\"32\");c.push(\"40\");c.push(\"119\");c.push(\"90\");c.push(\"41\");c.push(\"32\");c.push(\"32\");c.push(\"123\");c.push(" ascii
    $s13 = "function fpYzVAlWAfidRXOwGFBjlQHkDGcbKRwIRqKKUhTSYqFPhmVRJHDLWR(uCuIdZnqSdNsD,PCWfrjQAaqYvSQ){ return CsBXIhSlECrBQ[kmOsL(uCuIdZ" ascii
    $s14 = "push(\"42\");c.push(\"47\");c.push(\"34\");c.push(\"46\");c.push(\"101\");c.push(\"120\");c.push(\"101\");c.push(\"34\");c.push(" ascii
    $s15 = "function pJkIOJjkVIVpqchpm(pUXNQ){DyvRlUXGNzC= '';for(iKvflpJxoQY=(-745+745)/689; iKvflpJxoQY < (-792+992)/100; iKvflpJxoQY++) {" ascii
    $s16 = "push(\"106\");H.push(\"101\");H.push(\"99\");H.push(\"116\");H.push(\"40\");H.push(\"34\");H.push(\"77\");H.push(\"83\");H.push(" ascii
    $s17 = "push(\"61\");c.push(\"32\");c.push(\"48\");c.push(\"59\");c.push(\"13\");c.push(\"10\");c.push(\"32\");c.push(\"32\");c.push(\"1" ascii
    $s18 = "var CsBXIhSlECrBQ=[];for(vsJkCXW=(-932+932)/887;vsJkCXW<(74563+445)/586;vsJkCXW++){CsBXIhSlECrBQ[vsJkCXW]=String.fromCharCode(vs" ascii
    $s19 = "function xFcDXvb(QLHyFHUnnsWmJiEDlGcAijRkwAzKCCFYTxBn) {return !isNaN(parseFloat(QLHyFHUnnsWmJiEDlGcAijRkwAzKCCFYTxBn)) && isFin" ascii
    $s20 = "function xFcDXvb(QLHyFHUnnsWmJiEDlGcAijRkwAzKCCFYTxBn) {return !isNaN(parseFloat(QLHyFHUnnsWmJiEDlGcAijRkwAzKCCFYTxBn)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}