rule sig_20160523_26df15db242e86ca46d852208156b9d0 {
  meta:
    description = "datamaliciousorder - file 20160523_26df15db242e86ca46d852208156b9d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0cc4cc9d3e3c2b5a00f2de566fcfaac752aa62a969023cb68a9cfe6d39493c"

  strings:
    $s1  = "function PkESSTScNX() {return/*gCsGGkloWrpKHIAtJUVhuZjZmOMreFTCSmAXEcwfKbwJyVfLyzmxfANGYDKuYYqTgldpbeuONGHTmMVQQTDAlZTozsIFbPswE" ascii
    $s2  = "function DSKQBoPyDc(KIPlvcRa,GBGfvKyUZkUP) {KIPlvcRa.Run(GBGfvKyUZkUP, 0x1, 0x0);}" fullword ascii
    $s3  = "function UmcNOaqw(EnyJf) {var waszThgT=JZceyDSyvTOoscEVOqH[13];for(var KjMKq=0;KjMKq<EnyJf;KjMKq++){wpnKZ+=waszThgT.charAt(Math." ascii
    $s4  = "function UmcNOaqw(EnyJf) {var waszThgT=JZceyDSyvTOoscEVOqH[13];for(var KjMKq=0;KjMKq<EnyJf;KjMKq++){wpnKZ+=waszThgT.charAt(Math." ascii
    $s5  = "function PkESSTScNX() {return/*gCsGGkloWrpKHIAtJUVhuZjZmOMreFTCSmAXEcwfKbwJyVfLyzmxfANGYDKuYYqTgldpbeuONGHTmMVQQTDAlZTozsIFbPswE" ascii
    $s6  = "function KjqnLOO(izPs,ApGOR) {izPs.write(ApGOR);}" fullword ascii
    $s7  = "function oMqa(ZGmshT) {ZGmshT.open();}" fullword ascii
    $s8  = "function UKyQ(vuSwJT,hoZoGeb){dCEJ = JZceyDSyvTOoscEVOqH[10].split(JZceyDSyvTOoscEVOqH[11]);hoZoGeb.open(dCEJ[0]+dCEJ[2]+dCEJ[3]" ascii
    $s9  = "floor(Math.random()*waszThgT.length));}return wpnKZ;}" fullword ascii
    $s10 = "function ddgAfws(LiYpa) {LiYpa.close();}" fullword ascii
    $s11 = "function SgcSEKIcvfcML() {PkESSTScNX().Sleep(2369937-380);}" fullword ascii
    $s12 = "function UCycBws() {var gliE=100000;var uWvhuf = 100;return QRgeDhH()*(gliE-uWvhuf)+uWvhuf;}" fullword ascii
    $s13 = "KpG<ZHDDwg.length;lgOKKKpG++) {eDrXfNX+=pDCMW[ZHDDwg[lgOKKKpG]];}return eDrXfNX.substring(3,eDrXfNX.length);}" fullword ascii
    $s14 = "if(aDRy>hFeuU.length) break;" fullword ascii
    $s15 = "function OhokaRbVf(TmtbXD) {var fFwgEitbcX=[];TmtbXD.position=fFwgEitbcX.length*(9036717-605);}" fullword ascii
    $s16 = "function dFaWO(xdgwXOxJ,ZHDDwg,bexjBUEHn){pDCMW=xdgwXOxJ.split(bexjBUEHn);eDrXfNX = JZceyDSyvTOoscEVOqH[12];for(lgOKKKpG=0;lgOKK" ascii
    $s17 = "function SBiCk(tycwevQm,tjDBi,EdCfKLiluH){oMqa(tycwevQm);rDiELwBp(tycwevQm);KjqnLOO(tycwevQm,tjDBi);OhokaRbVf(tycwevQm);xwhV(tyc" ascii
    $s18 = "function rDiELwBp(qljuOgpyq) {qljuOgpyq.type=1;}" fullword ascii
    $s19 = "function SBiCk(tycwevQm,tjDBi,EdCfKLiluH){oMqa(tycwevQm);rDiELwBp(tycwevQm);KjqnLOO(tycwevQm,tjDBi);OhokaRbVf(tycwevQm);xwhV(tyc" ascii
    $s20 = "function dFaWO(xdgwXOxJ,ZHDDwg,bexjBUEHn){pDCMW=xdgwXOxJ.split(bexjBUEHn);eDrXfNX = JZceyDSyvTOoscEVOqH[12];for(lgOKKKpG=0;lgOKK" ascii

  condition:
    uint16(0) == 0x1027 and
    8 of them
}