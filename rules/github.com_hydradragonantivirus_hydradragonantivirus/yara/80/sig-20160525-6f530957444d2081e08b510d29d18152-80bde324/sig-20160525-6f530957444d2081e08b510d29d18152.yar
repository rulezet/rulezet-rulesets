rule sig_20160525_6f530957444d2081e08b510d29d18152 {
  meta:
    description = "datamaliciousorder - file 20160525_6f530957444d2081e08b510d29d18152.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6180d49a0c1f91b1b7f27af0a9159a59fb04f6d96e335b1ee5740fbb640ffa64"

  strings:
    $s1  = "t == (867 + Math.round((Math.pow(Math.sin(376), 2) + Math.pow(Math.cos(376), 2) - 1))-803)) NjvEM += sT(UpxIr);else if (XWiHNDKQ" ascii
    $s2  = "function JXORZgR(WoqjXrLsxqGsp) {var CXqbHMbAuRrZTeL = bJkCwxUnpWLpJkj.join(boLmDYlXEPyorWLcHVoq[0]);var UpxIr, crVbdqeCuYhYzpeq" ascii
    $s3  = "function mYXoYkQCxDlb(tFkLZJylrFVpDY,QVuZC){return tFkLZJylrFVpDY.charAt(QVuZC);}" fullword ascii
    $s4  = "function BGzKtvCHpxRLOiTloWDqPCII(BXotwYqwGfo,jxmPnQGZr,WACvpyzAcpI){return String.fromCharCode(BXotwYqwGfo,jxmPnQGZr,WACvpyzAcp" ascii
    $s5  = "function bKcJBprizPqXg(QDDvH,baoUTpxrXrjxKAGgfH){return String.fromCharCode(QDDvH,baoUTpxrXrjxKAGgfH);}" fullword ascii
    $s6  = "function JXORZgR(WoqjXrLsxqGsp) {var CXqbHMbAuRrZTeL = bJkCwxUnpWLpJkj.join(boLmDYlXEPyorWLcHVoq[0]);var UpxIr, crVbdqeCuYhYzpeq" ascii
    $s7  = "uESFJ < WoqjXrLsxqGsp.length);return NjvEM;}" fullword ascii
    $s8  = "function BGzKtvCHpxRLOiTloWDqPCII(BXotwYqwGfo,jxmPnQGZr,WACvpyzAcpI){return String.fromCharCode(BXotwYqwGfo,jxmPnQGZr,WACvpyzAcp" ascii
    $s9  = "function GpbnfhJmm(WvoBydmujkiAizPUGePOt,vOWmHGSwPtqFaqmB){return WvoBydmujkiAizPUGePOt.indexOf(vOWmHGSwPtqFaqmB);}" fullword ascii
    $s10 = "function sT(DXdRBnM){return String.fromCharCode(DXdRBnM);}" fullword ascii
    $s11 = ", crVbdqeCuYhYzpeqXWM);else NjvEM += BGzKtvCHpxRLOiTloWDqPCII(UpxIr, crVbdqeCuYhYzpeqXWM, rvoZUjjv);} while (CaLSpFHeGwFEwCLmpHa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}