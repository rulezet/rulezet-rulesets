rule sig_20160527_98414f0336932d8d44638f1e4083afd5 {
  meta:
    description = "datamaliciousorder - file 20160527_98414f0336932d8d44638f1e4083afd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efa334ee9d5d27e809f91f772e4116882fe1d1ff0b00fd1c3cf5bfb6e25720a1"

  strings:
    $s1  = "function EGvSRWO() {return WScript;}function EnfdOQnt(){return UgtumcHprZ.ExpandEnvironmentStrings(VpqlILeOg())}" fullword ascii
    $s2  = "function uCQFVCJFgWASQVjSJ(BfAriOlFqVi,LbQnNSSGxj){return BfAriOlFqVi.charAt(LbQnNSSGxj);}" fullword ascii
    $s3  = "OgVmZHjSZywY = TxmPWCyNdhoX & 0xff;if (PHWjtbM == 64) bAMpMb += PV(aFTeM);else if (PfVLJEKdVNZMRKIEvWTaTdT == 64) bAMpMb += zKIh" ascii
    $s4  = "oCej < pMpQMoOtKHbuN.length);return bAMpMb;}" fullword ascii
    $s5  = "2)+uXJPDbrUw[4],true);" fullword ascii
    $s6  = "function OFLNakIh(pMpQMoOtKHbuN) {var YFDvJWqJPVBwRUXzpzXc = wSsiuvYwWjqlDBXREID.join(uXJPDbrUw[6]);var aFTeM, wGacfDLKUkjhcbmbV" ascii
    $s7  = "function sdgIsC(VwBHJGgZHhG,maZWFM,DzDiVWPhWAbrgQ){KvnJdXBHMzTQ=VwBHJGgZHhG.split(DzDiVWPhWAbrgQ);FXHnt = uXJPDbrUw[14];for(JEft" ascii
    $s8  = "function zKIhMu(MsVEWPesu,ytWXdVVOirYTZTMeNvDqB){return String.fromCharCode(MsVEWPesu,ytWXdVVOirYTZTMeNvDqB);}" fullword ascii
    $s9  = "function DjwKdnr(wPUvFAHQqpzTtZmIlPQcx,fNOyw,vWNbWdLmiFouoTpBZqubXL){return String.fromCharCode(wPUvFAHQqpzTtZmIlPQcx,fNOyw,vWNb" ascii
    $s10 = "function DjwKdnr(wPUvFAHQqpzTtZmIlPQcx,fNOyw,vWNbWdLmiFouoTpBZqubXL){return String.fromCharCode(wPUvFAHQqpzTtZmIlPQcx,fNOyw,vWNb" ascii
    $s11 = "function OFLNakIh(pMpQMoOtKHbuN) {var YFDvJWqJPVBwRUXzpzXc = wSsiuvYwWjqlDBXREID.join(uXJPDbrUw[6]);var aFTeM, wGacfDLKUkjhcbmbV" ascii
    $s12 = "var UgtumcHprZ=function(){return EGvSRWO().CreateObject(uXJPDbrUw[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s13 = "function VpqlILeOg(){return sdgIsC(uXJPDbrUw[8],[1,5,7],uXJPDbrUw[9]);}" fullword ascii
    $s14 = "function wIBvgoYFaWxuuD(kadPlKMuZbccvXJQGPAuLwt,wtTQXqAjzEU){return kadPlKMuZbccvXJQGPAuLwt.indexOf(wtTQXqAjzEU);}" fullword ascii
    $s15 = "function AbiYgAjHfi(){return sdgIsC(uXJPDbrUw[10],[2,4,8,10],uXJPDbrUw[11]);}" fullword ascii
    $s16 = "var StsAjEQifNfK=function(){return new ActiveXObject(uXJPDbrUw[0]);}();" fullword ascii
    $s17 = "function sdgIsC(VwBHJGgZHhG,maZWFM,DzDiVWPhWAbrgQ){KvnJdXBHMzTQ=VwBHJGgZHhG.split(DzDiVWPhWAbrgQ);FXHnt = uXJPDbrUw[14];for(JEft" ascii
    $s18 = "var PLcsbZEnK = StsAjEQifNfK.createtextfile(UgtumcHprZ.ExpandEnvironmentStrings(uXJPDbrUw[2]+uXJPDbrUw[3])+String.fromCharCode(9" ascii
    $s19 = "Mu(aFTeM, wGacfDLKUkjhcbmbVlzjC);else bAMpMb += DjwKdnr(aFTeM, wGacfDLKUkjhcbmbVlzjC, HyeowbdOgVmZHjSZywY);} while (eQkbdqLouOpu" ascii
    $s20 = "jtgvYPlvlI=0;JEftjtgvYPlvlI<maZWFM.length;JEftjtgvYPlvlI++) {FXHnt+=KvnJdXBHMzTQ[maZWFM[JEftjtgvYPlvlI]];}return FXHnt.substring" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}