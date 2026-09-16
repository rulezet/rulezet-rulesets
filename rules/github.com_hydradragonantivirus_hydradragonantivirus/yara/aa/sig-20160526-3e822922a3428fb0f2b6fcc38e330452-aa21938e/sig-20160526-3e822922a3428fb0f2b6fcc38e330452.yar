rule sig_20160526_3e822922a3428fb0f2b6fcc38e330452 {
  meta:
    description = "datamaliciousorder - file 20160526_3e822922a3428fb0f2b6fcc38e330452.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebf1339460e6d6ab6e1bc749d1608ddd7b697c605d4598505240e655eb4b167a"

  strings:
    $s1  = "function yQgtH(wTnXGZCFrXhtj) {var qNHrJf = YKDexxPMYtGdewZAuX.join(GsXuTUcYJkgYXQbDwnCLI[0]);var ilEdyJSAzmmrxbazCK, CRBvZwOAY," ascii
    $s2  = " Math.round((Math.pow(Math.sin(10), 2) + Math.pow(Math.cos(10), 2) - 1))-681)) qeKda += GF(ilEdyJSAzmmrxbazCK);else if (nmRGrpgV" ascii
    $s3  = "function RBYYhJGWuODV(RjPtxVrp,WzlZZwkWtKNMRLqDlloQUA){return RjPtxVrp.charAt(WzlZZwkWtKNMRLqDlloQUA);}" fullword ascii
    $s4  = "hqkHliqpxHeCtiKXIHUZr(qNHrJf,RBYYhJGWuODV(wTnXGZCFrXhtj,GcmSMvwrFtdAGjxceQVXtfG++));nOUqkputtnJefFt = KiNHKWQRmvbSH<< (26 + Math" ascii
    $s5  = "function chqkHliqpxHeCtiKXIHUZr(NesMpocNyWWccZ,ZgRlUz){return NesMpocNyWWccZ.indexOf(ZgRlUz);}" fullword ascii
    $s6  = "Xt(ilEdyJSAzmmrxbazCK, CRBvZwOAY);else qeKda += SHHMRlghF(ilEdyJSAzmmrxbazCK, CRBvZwOAY, ViPWIHXNhyjnuUOu);} while (GcmSMvwrFtdA" ascii
    $s7  = "GjxceQVXtfG < wTnXGZCFrXhtj.length);return qeKda;}" fullword ascii
    $s8  = "function HvbeuBaiTsfgtbxOAOXt(bziOchSus,glhQoFBDqApJcGuyKiBbo){return String.fromCharCode(bziOchSus,glhQoFBDqApJcGuyKiBbo);}" fullword ascii
    $s9  = "function GF(dGyNnaDrSHXcBn){return String.fromCharCode(dGyNnaDrSHXcBn);}" fullword ascii
    $s10 = "function SHHMRlghF(fJMhNjO,idAjRYecdFrxuz,uNOmIt){return String.fromCharCode(fJMhNjO,idAjRYecdFrxuz,uNOmIt);}" fullword ascii
    $s11 = "function yQgtH(wTnXGZCFrXhtj) {var qNHrJf = YKDexxPMYtGdewZAuX.join(GsXuTUcYJkgYXQbDwnCLI[0]);var ilEdyJSAzmmrxbazCK, CRBvZwOAY," ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}