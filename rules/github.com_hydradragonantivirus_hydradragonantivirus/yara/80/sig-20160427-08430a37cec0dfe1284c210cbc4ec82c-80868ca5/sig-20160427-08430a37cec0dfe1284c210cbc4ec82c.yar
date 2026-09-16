rule sig_20160427_08430a37cec0dfe1284c210cbc4ec82c {
  meta:
    description = "datamaliciousorder - file 20160427_08430a37cec0dfe1284c210cbc4ec82c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00a8b8c38aa767119bd263aaa5167f71d793b2f53a74e5ec06d932feba48b344"

  strings:
    $s1  = " var SRnbA = 8983;SRnbA = 6382 - 3572;var hRBiuX = 8464;hRBiuX = 3843 * 8281;var lECH = 2895;var nvKLjL = 3758;var JHm = 7103;lE" ascii
    $s2  = " var SRnbA = 8983;SRnbA = 6382 - 3572;var hRBiuX = 8464;hRBiuX = 3843 * 8281;var lECH = 2895;var nvKLjL = 3758;var JHm = 7103;lE" ascii
    $s3  = " var vENt = 8845;vENt = 6162 - 3689;var PKipp = 390;var EWm = 5205;PKipp = EWm + vENt;" fullword ascii
    $s4  = "function FNnBC (aFKwSyOd) {" fullword ascii
    $s5  = "}switch(4) {" fullword ascii
    $s6  = "} var xvNR = true; " fullword ascii
    $s7  = "function VLLTdUN () {" fullword ascii
    $s8  = "function ONa () {" fullword ascii
    $s9  = "  var TYLIFfY = false; " fullword ascii
    $s10 = "var UyoFI = 48838;  } } }else{ function dfglflf () {" fullword ascii
    $s11 = " var OtUdOum = false; " fullword ascii
    $s12 = "}function SwTTDxk (PhQIt,tteDdl) {" fullword ascii
    $s13 = "function aKn () {" fullword ascii
    $s14 = "function riTXXNM () {" fullword ascii
    $s15 = "function pGS (ZaWY,mvowA) {" fullword ascii
    $s16 = " if(5 === true) {" fullword ascii
    $s17 = " var BCirn = true; " fullword ascii
    $s18 = " var BjeJG = false; " fullword ascii
    $s19 = "switch(DNcl) {" fullword ascii
    $s20 = " var SytvCEz = true; " fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}