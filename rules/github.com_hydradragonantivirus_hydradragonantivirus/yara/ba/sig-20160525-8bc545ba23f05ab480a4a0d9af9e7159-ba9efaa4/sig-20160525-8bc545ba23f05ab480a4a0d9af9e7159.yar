rule sig_20160525_8bc545ba23f05ab480a4a0d9af9e7159 {
  meta:
    description = "datamaliciousorder - file 20160525_8bc545ba23f05ab480a4a0d9af9e7159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e96de6e719577862abbf7454c29180b9f9d801b83c212942f81273db7ab2595"

  strings:
    $s1  = "Math.cos(512), 2) - 1))-152)) ghoTcjCweKkosEoxcBLfhcN += XO(RWiVHHDtTxutFmsqCHhiKn);else if (HHWtWWSDgdMIxjp == (758 + Math.roun" ascii
    $s2  = "function xRZztnsizU(TqljpMlgyjXWj) {var xnrEcxK = mrwNliNImyEc.join(ogTKsglPcJcS[0]);var RWiVHHDtTxutFmsqCHhiKn, yHQzrOQkUQHOyZI" ascii
    $s3  = "function cywyzXfIebNrnOehLyKZptM(XauqXvLUeFxMwKLD,yZaRBSLbemqvfhTJLGk){return XauqXvLUeFxMwKLD.charAt(yZaRBSLbemqvfhTJLGk);}" fullword ascii
    $s4  = "function XO(pgRlC){return String.fromCharCode(pgRlC);}" fullword ascii
    $s5  = "function PViUP(lUUfvQIhpYx,SHgGzPakSKyylxmpQzCLWu,jokfijNcFRSB){return String.fromCharCode(lUUfvQIhpYx,SHgGzPakSKyylxmpQzCLWu,jo" ascii
    $s6  = "tFmsqCHhiKn, yHQzrOQkUQHOyZISEUD);else ghoTcjCweKkosEoxcBLfhcN += PViUP(RWiVHHDtTxutFmsqCHhiKn, yHQzrOQkUQHOyZISEUD, ylOjcDW);} " ascii
    $s7  = "function mOnmkCWYLvAXBPjFtiUfMgm(iqReoHPgQogUOMnQRSXpBxz,BqurBgPbFbjEP){return iqReoHPgQogUOMnQRSXpBxz.indexOf(BqurBgPbFbjEP);}" fullword ascii
    $s8  = "function PViUP(lUUfvQIhpYx,SHgGzPakSKyylxmpQzCLWu,jokfijNcFRSB){return String.fromCharCode(lUUfvQIhpYx,SHgGzPakSKyylxmpQzCLWu,jo" ascii
    $s9  = "function jbfbMtOhRvnMrsPZEG(kZJuOQjSdHVpFPgt,NuSazZGymeifOU){return String.fromCharCode(kZJuOQjSdHVpFPgt,NuSazZGymeifOU);}" fullword ascii
    $s10 = "function xRZztnsizU(TqljpMlgyjXWj) {var xnrEcxK = mrwNliNImyEc.join(ogTKsglPcJcS[0]);var RWiVHHDtTxutFmsqCHhiKn, yHQzrOQkUQHOyZI" ascii
    $s11 = "while (LUUJic < TqljpMlgyjXWj.length);return ghoTcjCweKkosEoxcBLfhcN;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}