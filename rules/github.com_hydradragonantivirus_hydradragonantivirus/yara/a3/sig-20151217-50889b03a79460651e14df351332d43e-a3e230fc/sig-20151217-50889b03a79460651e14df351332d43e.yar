rule sig_20151217_50889b03a79460651e14df351332d43e {
  meta:
    description = "datamaliciousorder - file 20151217_50889b03a79460651e14df351332d43e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b038f6d5e84c48a893cb6f4862532fb5c0260fe6e7d1bc7c047ac277dd28626b"

  strings:
    $s1  = "function TIbbmUcWQWAVhTbGa(hqjLN){NWjzvjMjABX= '';JkCNlZdvbVm=Math.round((Math.pow(Math.sin(649), 2) + Math.pow(Math.cos(649), 2" ascii
    $s2  = "ow(Math.cos(833), 2) - 1)));} pnunGfYeK[JkCNlZdvbVm]++;}JkCNlZdvbVm++;} return NWjzvjMjABX}" fullword ascii
    $s3  = "h.pow(Math.cos(474), 2) - 1)); while(true) { if(pnunGfYeK[JkCNlZdvbVm] > hqjLN[JkCNlZdvbVm].length-(110+473)/583) { break; } if " ascii
    $s4  = ") - 1));while(true){if (JkCNlZdvbVm >= (603+633)/206){break;}pnunGfYeK[JkCNlZdvbVm]=Math.round((Math.pow(Math.sin(474), 2) + Mat" ascii
    $s5  = "function TIbbmUcWQWAVhTbGa(hqjLN){NWjzvjMjABX= '';JkCNlZdvbVm=Math.round((Math.pow(Math.sin(649), 2) + Math.pow(Math.cos(649), 2" ascii
    $s6  = "function LuGgGns(olcmftyIZJfPYRSxWrubadbsFGQSdQIFQdih) {return !rUsMQqyHjgA(OfRlicsicmCciZl(olcmftyIZJfPYRSxWrubadbsFGQSdQIFQdih" ascii
    $s7  = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s8  = "function pYNqs(QnOxqjcqdNT,ybPPqcMSciZoa,DXWBePWi){SxLu=gYpuyXUXWlZAXwelK(QnOxqjcqdNT,ybPPqcMSciZoa);ngLaU=SxLu.toString(DXWBePW" ascii
    $s9  = "function A(yTjeTOwMdRsS,yhiMLwweKLBwpt){yTjeTOwMdRsS.push(yhiMLwweKLBwpt);}" fullword ascii
    $s10 = "function LuGgGns(olcmftyIZJfPYRSxWrubadbsFGQSdQIFQdih) {return !rUsMQqyHjgA(OfRlicsicmCciZl(olcmftyIZJfPYRSxWrubadbsFGQSdQIFQdih" ascii
    $s11 = "function RHtOiobUctLNiIDOPRzoSufOyqnlsvVLeugoNStvjrVEspMFgYOLum(BlgVcqeszZkeu,XONKPcFVIDrfzu){ return KaYmBaV[ryhBKBmz[pYNqs(Blg" ascii
    $s12 = "function RHtOiobUctLNiIDOPRzoSufOyqnlsvVLeugoNStvjrVEspMFgYOLum(BlgVcqeszZkeu,XONKPcFVIDrfzu){ return KaYmBaV[ryhBKBmz[pYNqs(Blg" ascii
    $s13 = "function OfRlicsicmCciZl(AuXYlhwhtshXYFgzuSr) {return parseFloat(AuXYlhwhtshXYFgzuSr);}" fullword ascii
    $s14 = "function b(AnNDTiTtcxdIsO,cqqWTnKdMbdGA,YROlAQezzYe) {AnNDTiTtcxdIsO[cqqWTnKdMbdGA]=YROlAQezzYe;}" fullword ascii
    $s15 = "function pYNqs(QnOxqjcqdNT,ybPPqcMSciZoa,DXWBePWi){SxLu=gYpuyXUXWlZAXwelK(QnOxqjcqdNT,ybPPqcMSciZoa);ngLaU=SxLu.toString(DXWBePW" ascii
    $s16 = "function RhOVNWvuKeKtShr(MkIidyxqztIzyjCnL,AWTiOUZRKrKxrcLzwBqAVKuNKzKWjJuhUW,IxBJosPwQtaLMRCVJYfgBqnwyTkMxlfdhKS){eval(MkIidyxq" ascii
    $s17 = "function gYpuyXUXWlZAXwelK(IoQtoayvMN,yJpPylyXkO) {return parseInt(IoQtoayvMN,yJpPylyXkO);}" fullword ascii
    $s18 = "var W = new Array();W[0]=[];W[0][0]='d';W[0][1]='a';W[0][2]='d';W[0][3]='a';W[0][4]='46';W[0][5]='3d';W[0][6]='42';W[0][7]='14';" ascii
    $s19 = "i);return ngLaU;}" fullword ascii
    $s20 = "function RhOVNWvuKeKtShr(MkIidyxqztIzyjCnL,AWTiOUZRKrKxrcLzwBqAVKuNKzKWjJuhUW,IxBJosPwQtaLMRCVJYfgBqnwyTkMxlfdhKS){eval(MkIidyxq" ascii

  condition:
    uint16(0) == 0x7972 and
    8 of them
}