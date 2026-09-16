rule sig_20160525_36784da588aa4bf389437d0cd4cc1156 {
  meta:
    description = "datamaliciousorder - file 20160525_36784da588aa4bf389437d0cd4cc1156.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "499d20700951a65bc40840659b1df1f2aea01d14d9f0dbc15c0ee0c49043cdec"

  strings:
    $s1  = "function cziauEJPXVjHu(ShfDeabnSVvnC) {var THAzbtFfNCQjkLDS = TEytynOvuJCBOqEicVJpara.join(gJnkENmbgqg[0]);var ykQSSUUiZaA, qgYq" ascii
    $s2  = ", 2) - 1))-882)) RRttQFMnJqGxefv += nADHQimAOqbZPYAoDnYm(ykQSSUUiZaA, qgYqIUfEsGewLHsNldthzv);else RRttQFMnJqGxefv += YxOgLRpOAP" ascii
    $s3  = "JqGxefv += mb(ykQSSUUiZaA);else if (nVNklzKrRuFTAawANy == (946 + Math.round((Math.pow(Math.sin(233), 2) + Math.pow(Math.cos(233)" ascii
    $s4  = "function gAwNjuNCRWCizsXrYnnZPSLg(wNGkAZuoZdIfKiucoHIJCiLl,KMjUqztwRNocwqCghI){return wNGkAZuoZdIfKiucoHIJCiLl.charAt(KMjUqztwRN" ascii
    $s5  = "function gAwNjuNCRWCizsXrYnnZPSLg(wNGkAZuoZdIfKiucoHIJCiLl,KMjUqztwRNocwqCghI){return wNGkAZuoZdIfKiucoHIJCiLl.charAt(KMjUqztwRN" ascii
    $s6  = "function YxOgLRpOAPFICvUx(tkeHOHfDGsRbaq,NQbeH,GQHvmEfyNoHvwDualLx){return String.fromCharCode(tkeHOHfDGsRbaq,NQbeH,GQHvmEfyNoHv" ascii
    $s7  = "function cziauEJPXVjHu(ShfDeabnSVvnC) {var THAzbtFfNCQjkLDS = TEytynOvuJCBOqEicVJpara.join(gJnkENmbgqg[0]);var ykQSSUUiZaA, qgYq" ascii
    $s8  = "function nADHQimAOqbZPYAoDnYm(eulObVzRJjNkQWByDqxX,ApzfYmxCNWb){return String.fromCharCode(eulObVzRJjNkQWByDqxX,ApzfYmxCNWb);}" fullword ascii
    $s9  = "function YxOgLRpOAPFICvUx(tkeHOHfDGsRbaq,NQbeH,GQHvmEfyNoHvwDualLx){return String.fromCharCode(tkeHOHfDGsRbaq,NQbeH,GQHvmEfyNoHv" ascii
    $s10 = "FICvUx(ykQSSUUiZaA, qgYqIUfEsGewLHsNldthzv, bdmbwiXsHfyPFeG);} while (GdtEtkAluCyNbco < ShfDeabnSVvnC.length);return RRttQFMnJqG" ascii
    $s11 = "function mb(BtEuEmFNaz){return String.fromCharCode(BtEuEmFNaz);}" fullword ascii
    $s12 = "function sDrJyBQtjHXopILGqPWofef(njSodNapxJWTUyWdWPsglT,TfbJzgYQnof){return njSodNapxJWTUyWdWPsglT.indexOf(TfbJzgYQnof);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}