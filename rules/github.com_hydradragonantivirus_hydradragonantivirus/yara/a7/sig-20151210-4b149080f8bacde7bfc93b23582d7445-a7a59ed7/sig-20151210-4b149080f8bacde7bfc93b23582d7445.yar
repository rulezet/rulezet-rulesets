rule sig_20151210_4b149080f8bacde7bfc93b23582d7445 {
  meta:
    description = "datamaliciousorder - file 20151210_4b149080f8bacde7bfc93b23582d7445.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfbf1d16b21d649ecf5f5c0b47fde8bc52041e942cb1de6a26a066800b9b89eb"

  strings:
    $s1  = " ZLPlo;}function KxiqhazXbndyuTV(fOUYQmHUBYMNdLtqG){eval(fOUYQmHUBYMNdLtqG)}" fullword ascii
    $s2  = "function cwJlz(FUtDarfRIfk,HUKZZqOtqGEeI,izMPeZCm){dIMu=parseInt(FUtDarfRIfk,HUKZZqOtqGEeI);ZLPlo=dIMu.toString(izMPeZCm);return" ascii
    $s3  = "function cwJlz(FUtDarfRIfk,HUKZZqOtqGEeI,izMPeZCm){dIMu=parseInt(FUtDarfRIfk,HUKZZqOtqGEeI);ZLPlo=dIMu.toString(izMPeZCm);return" ascii
    $s4  = "KyPqTJUB[pEljsXbcToT]=(-27+27)/221; while(true) { if(tKyPqTJUB[pEljsXbcToT] > FFUsZ[pEljsXbcToT].length-(431+373)/804) { break; " ascii
    $s5  = "function plrZLNhJbnDsVaDin(FFUsZ){lKCZczDGkID= '';for(pEljsXbcToT=(-621+621)/223; pEljsXbcToT < (269+121)/195; pEljsXbcToT++) {t" ascii
    $s6  = "pVQyyKR=(-237+237)/794;while(true){if(pVQyyKR>=(47911+985)/382){break;}eUkUNKBLQWBBX[pVQyyKR]=String.fromCharCode(pVQyyKR);pVQyy" ascii
    $s7  = "function YTgiOlKRzfDOzviKAoCoIKeFHUNCsyPaZHndvLLCNMUEnpVCHgpaBY(lCdJulrIebase,shybwCDOqEujdD){ return eUkUNKBLQWBBX[cwJlz(lCdJul" ascii
    $s8  = "function YTgiOlKRzfDOzviKAoCoIKeFHUNCsyPaZHndvLLCNMUEnpVCHgpaBY(lCdJulrIebase,shybwCDOqEujdD){ return eUkUNKBLQWBBX[cwJlz(lCdJul" ascii
    $s9  = "function plrZLNhJbnDsVaDin(FFUsZ){lKCZczDGkID= '';for(pEljsXbcToT=(-621+621)/223; pEljsXbcToT < (269+121)/195; pEljsXbcToT++) {t" ascii
    $s10 = " return lKCZczDGkID}" fullword ascii
    $s11 = "function xJWNpvGoViN(NWdwEaDx,ArbshX){return NWdwEaDx.split(ArbshX)}" fullword ascii
    $s12 = "pVQyyKR=(-237+237)/794;while(true){if(pVQyyKR>=(47911+985)/382){break;}eUkUNKBLQWBBX[pVQyyKR]=String.fromCharCode(pVQyyKR);pVQyy" ascii
    $s13 = "function sBfifqZ(gqBulAOSbocmRcADsKnZsHDwhUSSjIxZcOtn) {return !isNaN(parseFloat(gqBulAOSbocmRcADsKnZsHDwhUSSjIxZcOtn)) && isFin" ascii
    $s14 = "function sBfifqZ(gqBulAOSbocmRcADsKnZsHDwhUSSjIxZcOtn) {return !isNaN(parseFloat(gqBulAOSbocmRcADsKnZsHDwhUSSjIxZcOtn)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}