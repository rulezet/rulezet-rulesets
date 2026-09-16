rule sig_20160525_ae480ad7c29deefd83a5441666dcc1a1 {
  meta:
    description = "datamaliciousorder - file 20160525_ae480ad7c29deefd83a5441666dcc1a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbd2e29f4314540d72b4178f83d8ae307862ef59aefb4303f573fbadfa5d2c1a"

  strings:
    $s1  = "th.pow(Math.cos(994), 2) - 1))-441)) avMcMQzvWj += Ha(bGhAssfBPFfOYGhfwXf);else if (YREegohKXuXpwxMMJmxSY == (163 + Math.round((" ascii
    $s2  = "function XOHriK(dHhODGDAZlnUB) {var VJXLBugSYBJD = ESInIJFnhOjvY.join(DlpalcYjurNiPNX[0]);var bGhAssfBPFfOYGhfwXf, UVrwUtoWMNzaq" ascii
    $s3  = "function yXiyo(hKVAcdATdLbwjICGbpYJpzIS,tYECQnehaRdXDnHpoHETj){return hKVAcdATdLbwjICGbpYJpzIS.charAt(tYECQnehaRdXDnHpoHETj);}" fullword ascii
    $s4  = "function XOHriK(dHhODGDAZlnUB) {var VJXLBugSYBJD = ESInIJFnhOjvY.join(DlpalcYjurNiPNX[0]);var bGhAssfBPFfOYGhfwXf, UVrwUtoWMNzaq" ascii
    $s5  = "function ljSZerjpBqfgl(gEEgvxHv,ldiYQUCN){return gEEgvxHv.indexOf(ldiYQUCN);}" fullword ascii
    $s6  = "function yAPPgucuzdlQuDvFBtFL(ZrFPZOrVMRCvHBKesX,XhqTPZpNoxpPS,aAaniKSPns){return String.fromCharCode(ZrFPZOrVMRCvHBKesX,XhqTPZp" ascii
    $s7  = ";else avMcMQzvWj += yAPPgucuzdlQuDvFBtFL(bGhAssfBPFfOYGhfwXf, UVrwUtoWMNzaq, XlLuxmaCwbBQAecsp);} while (WISqWHbs < dHhODGDAZlnU" ascii
    $s8  = "function cgnBYrntRFh(AWVpJr,bRlBBBlLHhPuBtZO){return String.fromCharCode(AWVpJr,bRlBBBlLHhPuBtZO);}" fullword ascii
    $s9  = "B.length);return avMcMQzvWj;}" fullword ascii
    $s10 = "function Ha(etmBmRHvPWafvgRCNtGjPZ){return String.fromCharCode(etmBmRHvPWafvgRCNtGjPZ);}" fullword ascii
    $s11 = "function yAPPgucuzdlQuDvFBtFL(ZrFPZOrVMRCvHBKesX,XhqTPZpNoxpPS,aAaniKSPns){return String.fromCharCode(ZrFPZOrVMRCvHBKesX,XhqTPZp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}