rule sig_20151215_a320e88fede5862fe05b7f24761bc047 {
  meta:
    description = "datamaliciousorder - file 20151215_a320e88fede5862fe05b7f24761bc047.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03c6aabb5482158c13fe927def368f06a39cbc690e7ce75927cefbaf6a5609d5"

  strings:
    $s1  = "Math.pow(Math.cos(693), 2) - 1)); while(true) { if(SIesbCcyO[NwkoMKBTleN] > tMONc[NwkoMKBTleN].length-(737+229)/966) { break; } " ascii
    $s2  = "h.pow(Math.cos(746), 2) - 1)));} SIesbCcyO[NwkoMKBTleN]++;}} return zdPfIjOnOLN}" fullword ascii
    $s3  = "function pCPdhLpbPSqzRYGJP(tMONc){zdPfIjOnOLN= E[1824];for(NwkoMKBTleN=Math.round((Math.pow(Math.sin(794), 2) + Math.pow(Math.co" ascii
    $s4  = "function pCPdhLpbPSqzRYGJP(tMONc){zdPfIjOnOLN= E[1824];for(NwkoMKBTleN=Math.round((Math.pow(Math.sin(794), 2) + Math.pow(Math.co" ascii
    $s5  = "function d(GgBOjxKLmXXR,SMfdziVoLxGokD){GgBOjxKLmXXR.push(SMfdziVoLxGokD);}function v5(qrZHHYKsroChGvMl){if(pxWKWQt(qrZHHYKsroCh" ascii
    $s6  = "GvMl)) {return (String.fromCharCode(qrZHHYKsroChGvMl) + String.fromCharCode((11157+148)/323));}}" fullword ascii
    $s7  = "function pxWKWQt(DfgcneZwJzIexAAWRIiLlSDdQJVsawlDJNBP) {return !isNaN(parseFloat(DfgcneZwJzIexAAWRIiLlSDdQJVsawlDJNBP)) && isFin" ascii
    $s8  = "function pxWKWQt(DfgcneZwJzIexAAWRIiLlSDdQJVsawlDJNBP) {return !isNaN(parseFloat(DfgcneZwJzIexAAWRIiLlSDdQJVsawlDJNBP)) && isFin" ascii
    $s9  = "var E=new Array();" fullword ascii
    $s10 = "function jLuji(MZQMHrOzrEZ,oHlMoHaWoSaub,jvwTHkgj){svLW=parseInt(MZQMHrOzrEZ,oHlMoHaWoSaub);ersFa=svLW.toString(jvwTHkgj);return" ascii
    $s11 = " ersFa;}function ofrgAAJHeAVSTea(LgmStshPiQHXQFyWI,LLeWDtwTxuedvgKXQnThYcjXFgmLCendNm,UzszhsWXIAstSnduyBNjsstaLvkrYOSMzHq){eval(" ascii
    $s12 = "function nEEihuoLXmbgnfBmZqgrPhrOibLXwSLaLXUEJOBuyPhBxlBStCXorI(BkiwscpJpsqZE,YpqzSwYLEWpIYl){ return aoADKAe[axdZOWjt[jLuji(Bki" ascii
    $s13 = "function d(GgBOjxKLmXXR,SMfdziVoLxGokD){GgBOjxKLmXXR.push(SMfdziVoLxGokD);}function v5(qrZHHYKsroChGvMl){if(pxWKWQt(qrZHHYKsroCh" ascii
    $s14 = "function ofrgAAJHeAVSTea(LgmStshPiQHXQFyWI){eval(LgmStshPiQHXQFyWI)}" fullword ascii
    $s15 = "function MfvwHjzfHPD(qoDmyAxp,zQBwiY){return qoDmyAxp.split(zQBwiY)}" fullword ascii
    $s16 = "function jLuji(MZQMHrOzrEZ,oHlMoHaWoSaub,jvwTHkgj){svLW=parseInt(MZQMHrOzrEZ,oHlMoHaWoSaub);ersFa=svLW.toString(jvwTHkgj);return" ascii
    $s17 = "function nEEihuoLXmbgnfBmZqgrPhrOibLXwSLaLXUEJOBuyPhBxlBStCXorI(BkiwscpJpsqZE,YpqzSwYLEWpIYl){ return aoADKAe[axdZOWjt[jLuji(Bki" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}