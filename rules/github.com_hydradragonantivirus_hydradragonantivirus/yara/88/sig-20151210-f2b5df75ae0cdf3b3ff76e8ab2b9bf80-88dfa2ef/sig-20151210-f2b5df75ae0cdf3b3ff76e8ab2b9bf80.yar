rule sig_20151210_f2b5df75ae0cdf3b3ff76e8ab2b9bf80 {
  meta:
    description = "datamaliciousorder - file 20151210_f2b5df75ae0cdf3b3ff76e8ab2b9bf80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b1dd946dc62dad6cba378a209dbac7993ed9bd5d155bfe180b06c2cf04a4868"

  strings:
    $s1  = "function XdgoIux(EgGXHpCGwPvnnOfwSXiOKKKNmawnSHKeipWw) {return !isNaN(parseFloat(EgGXHpCGwPvnnOfwSXiOKKKNmawnSHKeipWw)) && isFin" ascii
    $s2  = "function XdgoIux(EgGXHpCGwPvnnOfwSXiOKKKNmawnSHKeipWw) {return !isNaN(parseFloat(EgGXHpCGwPvnnOfwSXiOKKKNmawnSHKeipWw)) && isFin" ascii
    $s3  = "jDKKbXN[mpNrnCouqyi]=(-675+675)/749; while(true) { if(RWjDKKbXN[mpNrnCouqyi] > hlxGx[mpNrnCouqyi].length-(434+154)/588) { break;" ascii
    $s4  = "function ZbFDr(kvEIXLVBJnI,NlvCNHgMKSzKa,gVVNobAk){cvMS=parseInt(kvEIXLVBJnI,NlvCNHgMKSzKa);ZYTGQ=cvMS.toString(gVVNobAk);return" ascii
    $s5  = "}} return nuoRcHaVORC}" fullword ascii
    $s6  = "function SPFYZefkOKvRUHgFt(hlxGx){nuoRcHaVORC= '';for(mpNrnCouqyi=(-846+846)/971; mpNrnCouqyi < (-360+364)/2; mpNrnCouqyi++) {RW" ascii
    $s7  = "quTSiXM=(-240+240)/992;while(true){if(quTSiXM>=(66923+661)/528){break;}fgtAEKTQsYjJN[quTSiXM]=String.fromCharCode(quTSiXM);quTSi" ascii
    $s8  = "function ZbFDr(kvEIXLVBJnI,NlvCNHgMKSzKa,gVVNobAk){cvMS=parseInt(kvEIXLVBJnI,NlvCNHgMKSzKa);ZYTGQ=cvMS.toString(gVVNobAk);return" ascii
    $s9  = " ZYTGQ;}function yGAzRwpgniXErUw(dUyvOgHYTUMtEMBGo){eval(dUyvOgHYTUMtEMBGo)}" fullword ascii
    $s10 = "function SPFYZefkOKvRUHgFt(hlxGx){nuoRcHaVORC= '';for(mpNrnCouqyi=(-846+846)/971; mpNrnCouqyi < (-360+364)/2; mpNrnCouqyi++) {RW" ascii
    $s11 = "function EDJkuxxQjiCVjvsygHCsfvHkXFyfbFrbumdKtmHfedgFpPKFkBgPBl(MIfwQOopiBMKh,ZRbePdhCzGMBgg){ return fgtAEKTQsYjJN[ZbFDr(MIfwQO" ascii
    $s12 = "function epghEefzZUW(HpTiVIkI,UqroPy){return HpTiVIkI.split(UqroPy)}" fullword ascii
    $s13 = "quTSiXM=(-240+240)/992;while(true){if(quTSiXM>=(66923+661)/528){break;}fgtAEKTQsYjJN[quTSiXM]=String.fromCharCode(quTSiXM);quTSi" ascii
    $s14 = "function EDJkuxxQjiCVjvsygHCsfvHkXFyfbFrbumdKtmHfedgFpPKFkBgPBl(MIfwQOopiBMKh,ZRbePdhCzGMBgg){ return fgtAEKTQsYjJN[ZbFDr(MIfwQO" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}