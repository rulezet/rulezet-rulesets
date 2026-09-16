rule sig_20160520_129f86bfe509f13f08de2da2e5f0a142 {
  meta:
    description = "datamaliciousorder - file 20160520_129f86bfe509f13f08de2da2e5f0a142.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "211155eaacc550bb5295bca0d0a3aae51bd4aa7afa16d36e65980493d308965b"

  strings:
    $s1  = "function cldIYfSc(PDFfA) {var jaiDcqfV=ShtFQrrdmo[2];for(var Nlndw=0;Nlndw<PDFfA;Nlndw++){YyXHm+=jaiDcqfV.charAt(Math.floor(Math" ascii
    $s2  = "function cldIYfSc(PDFfA) {var jaiDcqfV=ShtFQrrdmo[2];for(var Nlndw=0;Nlndw<PDFfA;Nlndw++){YyXHm+=jaiDcqfV.charAt(Math.floor(Math" ascii
    $s3  = "function QfOEm(KNTKGada,SfRBSh,xfGLFeFWB){qbOCq=KNTKGada.split(xfGLFeFWB);DwLWiKm = ShtFQrrdmo[13];for(pNsWfEfb=0;pNsWfEfb<SfRBS" ascii
    $s4  = "if (SjJPAyY==0) break;" fullword ascii
    $s5  = "function kqALp(mKtOlskH,TiDsn,toTbJLIlrK){mKtOlskH.open();mKtOlskH.type = 1;mKtOlskH.write(TiDsn);mKtOlskH.position = 0;mKtOlskH" ascii
    $s6  = "function kqALp(mKtOlskH,TiDsn,toTbJLIlrK){mKtOlskH.open();mKtOlskH.type = 1;mKtOlskH.write(TiDsn);mKtOlskH.position = 0;mKtOlskH" ascii
    $s7  = "function KxaE(yQYkVU,UVAQbCm){gexC = ShtFQrrdmo[11].split(ShtFQrrdmo[12]);UVAQbCm.open(gexC[0]+gexC[2]+gexC[3], yQYkVU, false);U" ascii
    $s8  = "function QfOEm(KNTKGada,SfRBSh,xfGLFeFWB){qbOCq=KNTKGada.split(xfGLFeFWB);DwLWiKm = ShtFQrrdmo[13];for(pNsWfEfb=0;pNsWfEfb<SfRBS" ascii
    $s9  = "h.length;pNsWfEfb++) {DwLWiKm+=qbOCq[SfRBSh[pNsWfEfb]];}return DwLWiKm.substring(3,DwLWiKm.length);}" fullword ascii
    $s10 = ".random()*jaiDcqfV.length));}return YyXHm;}" fullword ascii
    $s11 = "function VzZBDzC() {var LIBo=100000;var YdCQag = 100;return Math.random()*(LIBo-YdCQag)+YdCQag;}" fullword ascii
    $s12 = "function UrBQqoUcj(bltGmyXRm,lRstWet,AEqHZGFs){" fullword ascii
    $s13 = "function rzjCWT(WYgdbX){return WYgdbX.ExpandEnvironmentStrings(ShtFQrrdmo[10])}" fullword ascii
    $s14 = "function KxaE(yQYkVU,UVAQbCm){gexC = ShtFQrrdmo[11].split(ShtFQrrdmo[12]);UVAQbCm.open(gexC[0]+gexC[2]+gexC[3], yQYkVU, false);U" ascii
    $s15 = "function lWaBn(WYgdbX){return new ActiveXObject(WYgdbX);}" fullword ascii
    $s16 = "try{SjJPAyY=UrBQqoUcj(cucCl[FCXt], VzZBDzC() + ShtFQrrdmo[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}