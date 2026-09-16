rule sig_20151217_02f47403bf0ef815c8301956da5dd4a2 {
  meta:
    description = "datamaliciousorder - file 20151217_02f47403bf0ef815c8301956da5dd4a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cdcddf5977f5e676b89a2bbc23ca56b7d55cec816a8f00daab24b49c9457e3f"

  strings:
    $s1  = "function jEbFirOouazoOQVXL(NPByk){uZrgxivxdAS= '';zuYrPWXrhLY=Math.round((Math.pow(Math.sin(998), 2) + Math.pow(Math.cos(998), 2" ascii
    $s2  = ") - 1));while(true){if (zuYrPWXrhLY >= (-887+953)/11){break;}qNFgfEQwo[zuYrPWXrhLY]=Math.round((Math.pow(Math.sin(229), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(229), 2) - 1)); while(true) { if(qNFgfEQwo[zuYrPWXrhLY] > NPByk[zuYrPWXrhLY].length-(-22+860)/838) { break; } if " ascii
    $s4  = "ow(Math.cos(101), 2) - 1)));} qNFgfEQwo[zuYrPWXrhLY]++;}zuYrPWXrhLY++;} return uZrgxivxdAS}" fullword ascii
    $s5  = "function jEbFirOouazoOQVXL(NPByk){uZrgxivxdAS= '';zuYrPWXrhLY=Math.round((Math.pow(Math.sin(998), 2) + Math.pow(Math.cos(998), 2" ascii
    $s6  = "function nebdaAp(SZQnhKpgwnyQTqkfQwejhECrxglhPGnxkxQg) {return !huWeQoTejxk(LzWjukZokoLgEeb(SZQnhKpgwnyQTqkfQwejhECrxglhPGnxkxQg" ascii
    $s7  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s8  = "function nebdaAp(SZQnhKpgwnyQTqkfQwejhECrxglhPGnxkxQg) {return !huWeQoTejxk(LzWjukZokoLgEeb(SZQnhKpgwnyQTqkfQwejhECrxglhPGnxkxQg" ascii
    $s9  = "function huWeQoTejxk(oJLESQaZvQxCxW) {return isNaN(oJLESQaZvQxCxW);}" fullword ascii
    $s10 = "function iHNMfMKoqYjsmUn(HqGWozQlCJEsYlywh,ZDWhlNvYRqrerSbqdbFAHlwOlujtcyedWs,iyaFAysDuPJNoPnNaGknTAdNshBFNRMYrmg){eval(HqGWozQl" ascii
    $s11 = ",'N','V','q',':','.','R','W','/','y','R','X','p','h','0','Y','l','.','3','O','!','T','%','&','Z','[','/','x',';','2','q',String." ascii
    $s12 = "function LzApbgWoXXYKwxXpB(FFmMehhxBc,lZRJsYYGsd) {return parseInt(FFmMehhxBc,lZRJsYYGsd);}" fullword ascii
    $s13 = "function s(LwsxxMZMplIK,OJNEaaRlFXKfME){LwsxxMZMplIK.push(OJNEaaRlFXKfME);}" fullword ascii
    $s14 = "function UHqanHDnkXDXYtWSDetbHSPEIzMtjPeEPsIJARCEwyZNacMpKVgnZb(ozfWuvcMrHoXY,MBvCooyHZWinrj){ return ukinqoc[VwPalwOW[rHhYw(ozf" ascii
    $s15 = "function LzWjukZokoLgEeb(WPvLUccxQbITPhtPrUl) {return parseFloat(WPvLUccxQbITPhtPrUl);}" fullword ascii
    $s16 = "function gYKVuShjkALa(nafFIBKMXGAMC) {return isFinite(nafFIBKMXGAMC);}" fullword ascii
    $s17 = "K);return LzNPr;}" fullword ascii
    $s18 = "function iHNMfMKoqYjsmUn(HqGWozQlCJEsYlywh,ZDWhlNvYRqrerSbqdbFAHlwOlujtcyedWs,iyaFAysDuPJNoPnNaGknTAdNshBFNRMYrmg){eval(HqGWozQl" ascii
    $s19 = "function UHqanHDnkXDXYtWSDetbHSPEIzMtjPeEPsIJARCEwyZNacMpKVgnZb(ozfWuvcMrHoXY,MBvCooyHZWinrj){ return ukinqoc[VwPalwOW[rHhYw(ozf" ascii
    $s20 = "function t(vxsLQGjsTiaBfF,KmjYYHBavzopo,UGoSnKTeCFC) {vxsLQGjsTiaBfF[KmjYYHBavzopo]=UGoSnKTeCFC;}" fullword ascii

  condition:
    uint16(0) == 0x7756 and
    8 of them
}