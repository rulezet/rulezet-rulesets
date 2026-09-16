rule sig_20160525_6b0c774461252c6ddcfaf5102b575dfe {
  meta:
    description = "datamaliciousorder - file 20160525_6b0c774461252c6ddcfaf5102b575dfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a70dc8796d2832b439413dbf438098fdcb66dc71d2cfc8d07e37fe50dae54df"

  strings:
    $s1  = " 2) - 1))-27)) sIWVMiavgxgFTlHhtXvVNRX += Mn(uNzidCdTcDMU);else if (zizOwK == (108 + Math.round((Math.pow(Math.sin(503), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(503), 2) - 1))-44)) sIWVMiavgxgFTlHhtXvVNRX += hAdMExYZ(uNzidCdTcDMU, CANXdVnmUtUXBZFEmPecIgj);else sIWVMiavgxgF" ascii
    $s3  = "function ylCrWXbP(XRtAzvVprrxXA) {var XLDXeTkMp = Tgaqa.join(WVPie[0]);var uNzidCdTcDMU, CANXdVnmUtUXBZFEmPecIgj, hcChEsjAeXGEQW" ascii
    $s4  = "function HwgGqfLMRmHBMeWkKk(uHGMSCmmw,POhglYDAfBg){return uHGMSCmmw.charAt(POhglYDAfBg);}" fullword ascii
    $s5  = "rrxXA.length);return sIWVMiavgxgFTlHhtXvVNRX;}" fullword ascii
    $s6  = "function Mn(imbVCNpyNLApXHMhUEgjTI){return String.fromCharCode(imbVCNpyNLApXHMhUEgjTI);}" fullword ascii
    $s7  = "function hAdMExYZ(bZOUgXzJDZAGlB,lQQlAKERpsc){return String.fromCharCode(bZOUgXzJDZAGlB,lQQlAKERpsc);}" fullword ascii
    $s8  = "function OlnMWwkxyC(jlbJKtpbXmdXrVLkyJ,fSOuRAdUqzqpVIgMwBp){return jlbJKtpbXmdXrVLkyJ.indexOf(fSOuRAdUqzqpVIgMwBp);}" fullword ascii
    $s9  = "function ylCrWXbP(XRtAzvVprrxXA) {var XLDXeTkMp = Tgaqa.join(WVPie[0]);var uNzidCdTcDMU, CANXdVnmUtUXBZFEmPecIgj, hcChEsjAeXGEQW" ascii
    $s10 = "function fgvZlCoCasW(SGFLI,gwNxdOtpJUAVjpQkltic,cnGmGNzNjt){return String.fromCharCode(SGFLI,gwNxdOtpJUAVjpQkltic,cnGmGNzNjt);}" fullword ascii
    $s11 = "TlHhtXvVNRX += fgvZlCoCasW(uNzidCdTcDMU, CANXdVnmUtUXBZFEmPecIgj, hcChEsjAeXGEQWYmIEp);} while (fQYxElFtLcpltYNxtrCWw < XRtAzvVp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}