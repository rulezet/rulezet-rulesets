rule sig_20160531_34794f284dca84308e8167db99061190 {
  meta:
    description = "datamaliciousorder - file 20160531_34794f284dca84308e8167db99061190.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cffd5eec21ee706d466107141a2c660a69a66ad0880c14da2ae700b14ad9cdd5"

  strings:
    $s1  = "var WGnnlXA=function(){return WScript.CreateObject(uznaKzFWalm[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ktmRZmVMo(ktUioqPl,PPraWszqMPGfJkpY){return ktUioqPl.charAt(PPraWszqMPGfJkpY);}" fullword ascii
    $s3  = "function HwWnQnfYRSAHIowuMgiYHwvP(ZndfpyGkFYOolHoLxGU,mMJbiNTLjzmQ){return ZndfpyGkFYOolHoLxGU.indexOf(mMJbiNTLjzmQ);}" fullword ascii
    $s4  = "function sBuoFqH(cnEzpIfohQbDXL,ITjVRJ) {var VnVbErlqEVvsJ=[uznaKzFWalm[15]];cnEzpIfohQbDXL[VnVbErlqEVvsJ[0]]" fullword ascii
    $s5  = "function trGOWYfapBaVIlfttKbYRk(hduFdiqsHXYpNOBLN,MhIdOAMCZFf,NDZdMjW){return String.fromCharCode(hduFdiqsHXYpNOBLN,MhIdOAMCZFf," ascii
    $s6  = "function qkz(mXSkWEbsxoYV){return String.fromCharCode(mXSkWEbsxoYV);}" fullword ascii
    $s7  = "(ITjVRJ,0x1,0x0)}function GJbhlY(hfHgyGSuP,SbkkrqZhIe,UglozVyQWoJFqc){var dOobwdwIPLP=hfHgyGSuP.createtextfile(SbkkrqZhIe,true);" ascii
    $s8  = "function CNZJJYuarydv(zNYdCZO,DptokJQvoFVoX,DBkCmS){qONDvwGT=zNYdCZO.split(DBkCmS);nlVNQeSIIgw = uznaKzFWalm[0];for(ItrqEomiYkRu" ascii
    $s9  = "function MYqqvut(){return CNZJJYuarydv(uznaKzFWalm[9],[1,5,7],uznaKzFWalm[10]);}" fullword ascii
    $s10 = "function FdpCbsIbULwfA(aHwnAhFUgSEub) {var KXRlgnjlgKPm = DtOLsV.join(uznaKzFWalm[7]);var wknxJbyooAfZ, eDiRwuknjXOTadVEbQ, xbJH" ascii
    $s11 = "var lwxrw=function(){return new ActiveXObject(uznaKzFWalm[1]);}();" fullword ascii
    $s12 = "function trGOWYfapBaVIlfttKbYRk(hduFdiqsHXYpNOBLN,MhIdOAMCZFf,NDZdMjW){return String.fromCharCode(hduFdiqsHXYpNOBLN,MhIdOAMCZFf," ascii
    $s13 = "SrsXZdxpqnmgaFsLTN += jDcGKsowCmQ(wknxJbyooAfZ, eDiRwuknjXOTadVEbQ);else SrsXZdxpqnmgaFsLTN += trGOWYfapBaVIlfttKbYRk(wknxJbyooA" ascii
    $s14 = "function jxcMFTCgQZ(){return CNZJJYuarydv(uznaKzFWalm[13],[0,3,6],uznaKzFWalm[14]);}" fullword ascii
    $s15 = "fZ, eDiRwuknjXOTadVEbQ, xbJHdyttxxUKBKXHrZrVSS);} while (CXjUcfqaO < aHwnAhFUgSEub.length);return SrsXZdxpqnmgaFsLTN;}" fullword ascii
    $s16 = "function FdpCbsIbULwfA(aHwnAhFUgSEub) {var KXRlgnjlgKPm = DtOLsV.join(uznaKzFWalm[7]);var wknxJbyooAfZ, eDiRwuknjXOTadVEbQ, xbJH" ascii
    $s17 = "function CNZJJYuarydv(zNYdCZO,DptokJQvoFVoX,DBkCmS){qONDvwGT=zNYdCZO.split(DBkCmS);nlVNQeSIIgw = uznaKzFWalm[0];for(ItrqEomiYkRu" ascii
    $s18 = "(ITjVRJ,0x1,0x0)}function GJbhlY(hfHgyGSuP,SbkkrqZhIe,UglozVyQWoJFqc){var dOobwdwIPLP=hfHgyGSuP.createtextfile(SbkkrqZhIe,true);" ascii
    $s19 = "J=0;ItrqEomiYkRuJ<DptokJQvoFVoX.length;ItrqEomiYkRuJ++) {nlVNQeSIIgw+=qONDvwGT[DptokJQvoFVoX[ItrqEomiYkRuJ]];}return nlVNQeSIIgw" ascii
    $s20 = "ZrVSS = PWTIfwDTtnEghLfEWECi & 0xff;if (OLnRooOm == 64) SrsXZdxpqnmgaFsLTN += qkz(wknxJbyooAfZ);else if (ipqCgwLZPrtnedi == 64) " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}