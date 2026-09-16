rule sig_20160523_57ef20aa19ce7d8a7656f4a20cfb0d68 {
  meta:
    description = "datamaliciousorder - file 20160523_57ef20aa19ce7d8a7656f4a20cfb0d68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e994f1d0d334184ab62e8e6d824ce60ed56dce4bce5fbafc09c57d621bd11dbb"

  strings:
    $s1  = "function GbTqkKQZ(oFMdn) {var PnNOuxgw=UgoGv[13];for(var AGEkk=0;AGEkk<oFMdn;AGEkk++){mJAsF+=PnNOuxgw.charAt(Math.floor(Math.ran" ascii
    $s2  = "function vPbgAXoqUC() {return/*CwVhLYHWPCuyRcYTOIlwrRGRHUzcUUtCuSIyBPzoVHifjCuUZJgqoPCuEekaCrqlhKHAXDZXcGqoGtbXhEclcKsqELRErKLMA" ascii
    $s3  = "function mTHuwhSXlv(nLJusbfV,gUWEmhAuvbzO) {nLJusbfV.Run(gUWEmhAuvbzO, 0x1, 0x0);}" fullword ascii
    $s4  = "function GbTqkKQZ(oFMdn) {var PnNOuxgw=UgoGv[13];for(var AGEkk=0;AGEkk<oFMdn;AGEkk++){mJAsF+=PnNOuxgw.charAt(Math.floor(Math.ran" ascii
    $s5  = "function kwEQQ(bINnwp){return new ActiveXObject(bINnwp);}" fullword ascii
    $s6  = "function XBVLhr(bINnwp){return bINnwp.ExpandEnvironmentStrings(UgoGv[9])}" fullword ascii
    $s7  = "function SZeCE(aqCdyZMH,NvwtuB,ObIbtGIIH){GeinG=aqCdyZMH.split(ObIbtGIIH);wpWuuoC = UgoGv[12];for(rpYvGsEI=0;rpYvGsEI<NvwtuB.len" ascii
    $s8  = "function Clpw(qqokGG,GFrNjzv){QyFo = UgoGv[10].split(UgoGv[11]);GFrNjzv.open(QyFo[0]+QyFo[2]+QyFo[3], qqokGG, false);GFrNjzv.sen" ascii
    $s9  = "function gqXGvvIFGvcil() {vPbgAXoqUC().Sleep(2302440-326);}" fullword ascii
    $s10 = "dom()*PnNOuxgw.length));}return mJAsF;}" fullword ascii
    $s11 = "function SZeCE(aqCdyZMH,NvwtuB,ObIbtGIIH){GeinG=aqCdyZMH.split(ObIbtGIIH);wpWuuoC = UgoGv[12];for(rpYvGsEI=0;rpYvGsEI<NvwtuB.len" ascii
    $s12 = "function pCpyFKP(){return Math.random();}" fullword ascii
    $s13 = "function TLdgV(hXcCRFXr,lcTNT,rKpcKZVNgD){kTIZ(hXcCRFXr);uMrXwYaN(hXcCRFXr);yvVVznd(hXcCRFXr,lcTNT);lpvwyeDZY(hXcCRFXr);NzTH(hXc" ascii
    $s14 = "function uMrXwYaN(ODehWVGcY) {ODehWVGcY.type=1;}" fullword ascii
    $s15 = "if(tuMR>HKNkT.length) break;" fullword ascii
    $s16 = "gth;rpYvGsEI++) {wpWuuoC+=GeinG[NvwtuB[rpYvGsEI]];}return wpWuuoC.substring(3,wpWuuoC.length);}" fullword ascii
    $s17 = "function TLdgV(hXcCRFXr,lcTNT,rKpcKZVNgD){kTIZ(hXcCRFXr);uMrXwYaN(hXcCRFXr);yvVVznd(hXcCRFXr,lcTNT);lpvwyeDZY(hXcCRFXr);NzTH(hXc" ascii
    $s18 = "function Clpw(qqokGG,GFrNjzv){QyFo = UgoGv[10].split(UgoGv[11]);GFrNjzv.open(QyFo[0]+QyFo[2]+QyFo[3], qqokGG, false);GFrNjzv.sen" ascii
    $s19 = "function yvVVznd(RopJ,TKstR) {RopJ.write(TKstR);}" fullword ascii
    $s20 = "function EELUuXq(cPnRs) {cPnRs.close();}" fullword ascii

  condition:
    uint16(0) == 0x1627 and
    8 of them
}