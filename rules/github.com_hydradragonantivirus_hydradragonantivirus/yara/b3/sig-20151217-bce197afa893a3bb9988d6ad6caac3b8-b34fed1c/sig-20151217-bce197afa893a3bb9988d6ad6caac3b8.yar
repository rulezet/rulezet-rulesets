rule sig_20151217_bce197afa893a3bb9988d6ad6caac3b8 {
  meta:
    description = "datamaliciousorder - file 20151217_bce197afa893a3bb9988d6ad6caac3b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2210c6bdaf4c83b8589d3d24f85eca2a73c222036400bf15ca52d8b79b39fa3"

  strings:
    $s1  = "function iaCKMNUHhuMmZJLfT(tRkDK){ozRHovgoHWJ= '';jNnXcJWCoLR=Math.round((Math.pow(Math.sin(171), 2) + Math.pow(Math.cos(171), 2" ascii
    $s2  = ") - 1));while(true){if (jNnXcJWCoLR >= (343+755)/183){break;}SnkSGrmac[jNnXcJWCoLR]=Math.round((Math.pow(Math.sin(667), 2) + Mat" ascii
    $s3  = "pow(Math.cos(971), 2) - 1)));} SnkSGrmac[jNnXcJWCoLR]++;}jNnXcJWCoLR++;} return ozRHovgoHWJ}" fullword ascii
    $s4  = "h.pow(Math.cos(667), 2) - 1)); while(true) { if(SnkSGrmac[jNnXcJWCoLR] > tRkDK[jNnXcJWCoLR].length-(-209+948)/739) { break; } if" ascii
    $s5  = "function iaCKMNUHhuMmZJLfT(tRkDK){ozRHovgoHWJ= '';jNnXcJWCoLR=Math.round((Math.pow(Math.sin(171), 2) + Math.pow(Math.cos(171), 2" ascii
    $s6  = "bfTKSapkcCGmdBkZYSTJKqNhudhdZlgnnKt([tRkDK[jNnXcJWCoLR][SnkSGrmac[jNnXcJWCoLR]]], Math.round((Math.pow(Math.sin(971), 2) + Math." ascii
    $s7  = "function yiXIbnz(MTnZSNgpHlPcCKDZtkxekAndaZQIaoVbojiR) {return !cmutuZZQgFL(UuwswWoulbgufKa(MTnZSNgpHlPcCKDZtkxekAndaZQIaoVbojiR" ascii
    $s8  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s9  = "a);return KjIAW;}" fullword ascii
    $s10 = "function tQlpj(dXLYlBsvdGk,oPcQdfqdRTLLr,tzjRAILa){fHUo=SDBqrPNetGXcNhPdC(dXLYlBsvdGk,oPcQdfqdRTLLr);KjIAW=fHUo.toString(tzjRAIL" ascii
    $s11 = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s12 = "function qCiPvmDKhTbfmjP(MoTPwgzFuyJCLvtMI,gmiGduamdkfIDbLkGuPZSdTCKGtlxSKCib,CUObuUMBZxQPcDiUMWhwHNcJnZHgQyqZRVe){eval(MoTPwgzF" ascii
    $s13 = "function E(qXIGYtBWfsir,jkrJaqahTTRqdA){qXIGYtBWfsir.push(jkrJaqahTTRqdA);}" fullword ascii
    $s14 = "function DBIzracixMeQ(FkBtblLKmjmzr) {return isFinite(FkBtblLKmjmzr);}" fullword ascii
    $s15 = "function SDBqrPNetGXcNhPdC(hIlZlWjGSq,HFJUxVLAeC) {return parseInt(hIlZlWjGSq,HFJUxVLAeC);}" fullword ascii
    $s16 = "function tUjrAPmLCfEqwWiLNTUbfTKSapkcCGmdBkZYSTJKqNhudhdZlgnnKt(mfGjNuBPtpgOX,JyYptVOSDrZfoz){ return KIbomsS[ujkQaBNh[tQlpj(mfG" ascii
    $s17 = "function qCiPvmDKhTbfmjP(MoTPwgzFuyJCLvtMI,gmiGduamdkfIDbLkGuPZSdTCKGtlxSKCib,CUObuUMBZxQPcDiUMWhwHNcJnZHgQyqZRVe){eval(MoTPwgzF" ascii
    $s18 = "function tUjrAPmLCfEqwWiLNTUbfTKSapkcCGmdBkZYSTJKqNhudhdZlgnnKt(mfGjNuBPtpgOX,JyYptVOSDrZfoz){ return KIbomsS[ujkQaBNh[tQlpj(mfG" ascii
    $s19 = "function tQlpj(dXLYlBsvdGk,oPcQdfqdRTLLr,tzjRAILa){fHUo=SDBqrPNetGXcNhPdC(dXLYlBsvdGk,oPcQdfqdRTLLr);KjIAW=fHUo.toString(tzjRAIL" ascii
    $s20 = "function cmutuZZQgFL(GVqhOZgqXISIsI) {return isNaN(GVqhOZgqXISIsI);}" fullword ascii

  condition:
    uint16(0) == 0x6a75 and
    8 of them
}