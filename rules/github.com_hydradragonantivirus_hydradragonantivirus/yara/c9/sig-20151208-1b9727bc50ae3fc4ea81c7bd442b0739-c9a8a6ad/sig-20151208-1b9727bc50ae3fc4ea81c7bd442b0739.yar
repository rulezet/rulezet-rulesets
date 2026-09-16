rule sig_20151208_1b9727bc50ae3fc4ea81c7bd442b0739 {
  meta:
    description = "datamaliciousorder - file 20151208_1b9727bc50ae3fc4ea81c7bd442b0739.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b78920032d1f66c7f313c71730ee31eb8da37fa8c15698a7e89b8ce605c572a"

  strings:
    $s1  = "push(\"55\");i.push(\"49\");i.push(\"50\");i.push(\"52\");i.push(\"55\");i.push(\"53\");i.push(\"57\");i.push(\"56\");i.push(\"5" ascii
    $s2  = ");return ZFsrA;}function CPlUzheWBEqnTxU(vKbOpGMZrbissiDGD){eval(vKbOpGMZrbissiDGD)}" fullword ascii
    $s3  = "ZKCTZwFw[rAwrobYSvxd]=(-782+782)/422; while(true) { if(fZKCTZwFw[rAwrobYSvxd] > PPgdy[rAwrobYSvxd].length-(888+73)/961) { break;" ascii
    $s4  = "push(\"97\");d.push(\"114\");d.push(\"32\");d.push(\"74\");d.push(\"115\");d.push(\"32\");d.push(\"61\");d.push(\"32\");d.push(" ascii
    $s5  = "push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"34\");d.push(\"50\");d.push(\"46\");d.push(\"88\");d.push(\"77\");d.push(\"7" ascii
    $s6  = "var YwaSsHdHNNZHZ=[];for(hpBsRSg=(-495+495)/368;hpBsRSg<(122673+975)/966;hpBsRSg++){YwaSsHdHNNZHZ[hpBsRSg]=String.fromCharCode(h" ascii
    $s7  = "push(\"50\");i.push(\"50\");i.push(\"48\");i.push(\"48\");i.push(\"45\");i.push(\"54\");i.push(\"54\");i.push(\"50\");i.push(\"4" ascii
    $s8  = "function qwOlFnLXutubgikYb(PPgdy){YDJTfcKGtWl= '';for(rAwrobYSvxd=(-636+636)/657; rAwrobYSvxd < (989+477)/733; rAwrobYSvxd++) {f" ascii
    $s9  = "function qwOlFnLXutubgikYb(PPgdy){YDJTfcKGtWl= '';for(rAwrobYSvxd=(-636+636)/657; rAwrobYSvxd < (989+477)/733; rAwrobYSvxd++) {f" ascii
    $s10 = "function xkTxkqJaDpGPcSdRmPrvJVsuKoBwnwCBpfhpbLICsZLaVddCoHilhg(rrPQoGNzbqHoD,paIblGmMCEadtq){ return YwaSsHdHNNZHZ[npcHf(rrPQoG" ascii
    $s11 = ";}} return YDJTfcKGtWl}" fullword ascii
    $s12 = "push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"79\");i.push(\"75\");i.push(\"1" ascii
    $s13 = "push(\"121\");i.push(\"41\");i.push(\"59\");i.push(\"32\");i.push(\"105\");i.push(\"102\");i.push(\"32\");i.push(\"40\");i.push(" ascii
    $s14 = "pBsRSg)}function npcHf(InsHAzICVbS,nPsujjuzRxPtD,fRufRSDo){bqlX=parseInt(InsHAzICVbS,nPsujjuzRxPtD);ZFsrA=bqlX.toString(fRufRSDo" ascii
    $s15 = "push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"32\");i.push(\"3" ascii
    $s16 = "push(\"120\");d.push(\"32\");d.push(\"61\");d.push(\"32\");d.push(\"34\");d.push(\"65\");d.push(\"68\");d.push(\"79\");d.push(\"" ascii
    $s17 = "function xkTxkqJaDpGPcSdRmPrvJVsuKoBwnwCBpfhpbLICsZLaVddCoHilhg(rrPQoGNzbqHoD,paIblGmMCEadtq){ return YwaSsHdHNNZHZ[npcHf(rrPQoG" ascii
    $s18 = "push(\"47\");d.push(\"42\");d.push(\"79\");d.push(\"98\");d.push(\"67\");d.push(\"80\");d.push(\"49\");d.push(\"54\");d.push(\"5" ascii
    $s19 = "function GWDEiBWpaal(wERmnhXg,sXYxOs){return wERmnhXg.split(sXYxOs)}" fullword ascii
    $s20 = "function qKUaQMp(vGcEnCaKyJngMdMLjvFmAsAGkNrhRkqtHHqE) {return !isNaN(parseFloat(vGcEnCaKyJngMdMLjvFmAsAGkNrhRkqtHHqE)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}