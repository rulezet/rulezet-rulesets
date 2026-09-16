rule sig_20160523_9a134c0cc8b9880e5e48652128a8618f {
  meta:
    description = "datamaliciousorder - file 20160523_9a134c0cc8b9880e5e48652128a8618f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c12c82e9d2ffec5032ce788185e63c8154c01e19fd5259357b7937eb0afaf1"

  strings:
    $s1  = "function cFCdhqePDc(dbEscEEB,gXHKDKSlWnGy) {dbEscEEB.Run(gXHKDKSlWnGy, 0x1, 0x0);}" fullword ascii
    $s2  = "function ubjizlhbSU() {return/*JUiemyYJVwtdRtKaycyQlyvyvEGyHJskayXDaamRAoMnQRipdYLwferbRMDpDQmXezAERxHezUWCMPaJJirsVBOdGwknsrXev" ascii
    $s3  = "function lbDmpyGj(VXAfk) {var MwwXTYVm=hskAKod[13];for(var RFYHI=0;RFYHI<VXAfk;RFYHI++){XfbdW+=MwwXTYVm.charAt(Math.floor(Math.r" ascii
    $s4  = "function lbDmpyGj(VXAfk) {var MwwXTYVm=hskAKod[13];for(var RFYHI=0;RFYHI<VXAfk;RFYHI++){XfbdW+=MwwXTYVm.charAt(Math.floor(Math.r" ascii
    $s5  = "ength;SUJcPBkF++) {ePajjba+=xJHoE[fYoxTD[SUJcPBkF]];}return ePajjba.substring(3,ePajjba.length);}" fullword ascii
    $s6  = "function aZequeUrMpTVu() {ubjizlhbSU().Sleep(2325080-217);}" fullword ascii
    $s7  = "function dWNGmzWg(mFKbXhqWf) {mFKbXhqWf.type=1;}" fullword ascii
    $s8  = "function blBJrrKpJ(qCCPZf) {var FDDxjzxqTV=[];qCCPZf.position=FDDxjzxqTV.length*(9460928-817);}" fullword ascii
    $s9  = "function kkFDJ(yVZEHJ){return new ActiveXObject(yVZEHJ);}" fullword ascii
    $s10 = "function oPJv(uKtQQa,biwICvM){gagi = hskAKod[10].split(hskAKod[11]);biwICvM.open(gagi[0]+gagi[2]+gagi[3], uKtQQa, false);biwICvM" ascii
    $s11 = "function DZzvF(qmZHTgut,pWtUt,kyoLwcKiiI){dfpN(qmZHTgut);dWNGmzWg(qmZHTgut);WOEGgiF(qmZHTgut,pWtUt);blBJrrKpJ(qmZHTgut);zLpw(qmZ" ascii
    $s12 = "function WOEGgiF(Gapd,MHWDk) {Gapd.write(MHWDk);}" fullword ascii
    $s13 = "function sRtQa(clgxIcFi,fYoxTD,DSikfdNyM){xJHoE=clgxIcFi.split(DSikfdNyM);ePajjba = hskAKod[12];for(SUJcPBkF=0;SUJcPBkF<fYoxTD.l" ascii
    $s14 = "function YZxnGF(yVZEHJ){return yVZEHJ.ExpandEnvironmentStrings(hskAKod[9])}" fullword ascii
    $s15 = "function sRtQa(clgxIcFi,fYoxTD,DSikfdNyM){xJHoE=clgxIcFi.split(DSikfdNyM);ePajjba = hskAKod[12];for(SUJcPBkF=0;SUJcPBkF<fYoxTD.l" ascii
    $s16 = "function oPJv(uKtQQa,biwICvM){gagi = hskAKod[10].split(hskAKod[11]);biwICvM.open(gagi[0]+gagi[2]+gagi[3], uKtQQa, false);biwICvM" ascii
    $s17 = "function DZzvF(qmZHTgut,pWtUt,kyoLwcKiiI){dfpN(qmZHTgut);dWNGmzWg(qmZHTgut);WOEGgiF(qmZHTgut,pWtUt);blBJrrKpJ(qmZHTgut);zLpw(qmZ" ascii
    $s18 = "andom()*MwwXTYVm.length));}return XfbdW;}" fullword ascii
    $s19 = "function zLpw(hrlcVwJ,BDivGza) {hrlcVwJ.saveToFile(BDivGza, 2);}" fullword ascii
    $s20 = "function ubjizlhbSU() {return/*JUiemyYJVwtdRtKaycyQlyvyvEGyHJskayXDaamRAoMnQRipdYLwferbRMDpDQmXezAERxHezUWCMPaJJirsVBOdGwknsrXev" ascii

  condition:
    uint16(0) == 0x1627 and
    8 of them
}