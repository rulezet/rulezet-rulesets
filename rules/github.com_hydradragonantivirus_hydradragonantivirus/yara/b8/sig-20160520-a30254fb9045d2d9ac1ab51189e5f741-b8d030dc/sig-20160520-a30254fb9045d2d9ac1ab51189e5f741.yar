rule sig_20160520_a30254fb9045d2d9ac1ab51189e5f741 {
  meta:
    description = "datamaliciousorder - file 20160520_a30254fb9045d2d9ac1ab51189e5f741.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e3642c1c0106a19cc4602fe67bb3a0e81f45bcb66d888a8351e4fb7af337502"

  strings:
    $s1  = "function mCoXSXsZ(Mnpsx) {var ixzgUHtq=JsCjwGlqEhgyLQ[2];for(var jnzil=0;jnzil<Mnpsx;jnzil++){eOlMA+=ixzgUHtq.charAt(Math.floor(" ascii
    $s2  = "function mCoXSXsZ(Mnpsx) {var ixzgUHtq=JsCjwGlqEhgyLQ[2];for(var jnzil=0;jnzil<Mnpsx;jnzil++){eOlMA+=ixzgUHtq.charAt(Math.floor(" ascii
    $s3  = "Math.random()*ixzgUHtq.length));}return eOlMA;}" fullword ascii
    $s4  = "function XNUA(VusERe,XzYLIQb){GZHl = JsCjwGlqEhgyLQ[11].split(JsCjwGlqEhgyLQ[12]);XzYLIQb.open(GZHl[0]+GZHl[2]+GZHl[3], VusERe, " ascii
    $s5  = "LpRup.length;cTobPYAy++) {HgEuiKL+=xzAZg[OLpRup[cTobPYAy]];}return HgEuiKL.substring(3,HgEuiKL.length);}" fullword ascii
    $s6  = "function XNUA(VusERe,XzYLIQb){GZHl = JsCjwGlqEhgyLQ[11].split(JsCjwGlqEhgyLQ[12]);XzYLIQb.open(GZHl[0]+GZHl[2]+GZHl[3], VusERe, " ascii
    $s7  = "function XYUnZzX() {var qyVa=100000;var SvPPlm = 100;return Math.random()*(qyVa-SvPPlm)+SvPPlm;}" fullword ascii
    $s8  = "function wUMVH(DlVoueCf,NPXqy,pKGVfVnUhh){DlVoueCf.open();DlVoueCf.type = 1;DlVoueCf.write(NPXqy);DlVoueCf.position = 0;DlVoueCf" ascii
    $s9  = "function xBwgx(QTcKZkoP,OLpRup,dvCocGyzk){xzAZg=QTcKZkoP.split(dvCocGyzk);HgEuiKL = JsCjwGlqEhgyLQ[13];for(cTobPYAy=0;cTobPYAy<O" ascii
    $s10 = "function wUMVH(DlVoueCf,NPXqy,pKGVfVnUhh){DlVoueCf.open();DlVoueCf.type = 1;DlVoueCf.write(NPXqy);DlVoueCf.position = 0;DlVoueCf" ascii
    $s11 = "function xBwgx(QTcKZkoP,OLpRup,dvCocGyzk){xzAZg=QTcKZkoP.split(dvCocGyzk);HgEuiKL = JsCjwGlqEhgyLQ[13];for(cTobPYAy=0;cTobPYAy<O" ascii
    $s12 = "try{oTGZXiVlI(NWlHS[Gqut], XYUnZzX() + JsCjwGlqEhgyLQ[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function KywtI(dmyHoJ){return new ActiveXObject(dmyHoJ);}" fullword ascii
    $s14 = "function GlSdqA(dmyHoJ){return dmyHoJ.ExpandEnvironmentStrings(JsCjwGlqEhgyLQ[10])}" fullword ascii
    $s15 = "false);XzYLIQb.send();}" fullword ascii
    $s16 = "function oTGZXiVlI(dCvVHOvIB,oDtOqKa,aEjdppQz){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}