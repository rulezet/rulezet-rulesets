rule sig_20160531_7577bd9e233e7ad528e4653f3eb9542e {
  meta:
    description = "datamaliciousorder - file 20160531_7577bd9e233e7ad528e4653f3eb9542e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3f8dceb981a1ca3fe3a0c0b5b847a33fca0963b007eae0811da7407d9285fee"

  strings:
    $s1  = "var hbEnqwOX=function(){return WScript.CreateObject(fAZNpUcbhfifBqL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ZlXao(FEhqwrGPZafTh) {var sNAzhah = dliUzYE.join(fAZNpUcbhfifBqL[7]);var IqxOEBGcPcyAtjObKzBNv, eRKINGNyzNqwnvwN, lxsEE" ascii
    $s3  = "function DpfRsuyVWOHVwKHRITnUb(aAYQz,pzbHvyWmDCOZ){return aAYQz.charAt(pzbHvyWmDCOZ);}" fullword ascii
    $s4  = "function jlAwDN(){return XEDcLVWJVg(fAZNpUcbhfifBqL[13],[0,3,6],fAZNpUcbhfifBqL[14]);}" fullword ascii
    $s5  = "(LMeWCjEZGDJJ,0x1,0x0)}function bjGcH(HqpjdGuaQArq,HNxpMpfHf,ELifNQspQCSVKJ){var IgAjnDXZxy=HqpjdGuaQArq.createtextfile(HNxpMpfH" ascii
    $s6  = "function TXbAp(EyrHjUcpVpoZtuvJxeI,cyRucZEFFkfEHMPfaXDnRJ){return String.fromCharCode(EyrHjUcpVpoZtuvJxeI,cyRucZEFFkfEHMPfaXDnRJ" ascii
    $s7  = "function CuWsIKEn(LumbJAzxpYHIOTBUvdBDngS,FQpjLDMrvgiOlMeeAV,EOeJYAxdbpvCsSHaiZ){return String.fromCharCode(LumbJAzxpYHIOTBUvdBD" ascii
    $s8  = "function kFIbMhtckldKC(zjkBAxinNOj,LMeWCjEZGDJJ) {var gUhwsAh=[fAZNpUcbhfifBqL[15]];zjkBAxinNOj[gUhwsAh[0]]" fullword ascii
    $s9  = "function JHajLcMuymNFRO(){return XEDcLVWJVg(fAZNpUcbhfifBqL[11],[2,4,8,10],fAZNpUcbhfifBqL[12]);}" fullword ascii
    $s10 = "f,true);IgAjnDXZxy.WriteLine(ELifNQspQCSVKJ);IgAjnDXZxy.Close();}" fullword ascii
    $s11 = "function TXbAp(EyrHjUcpVpoZtuvJxeI,cyRucZEFFkfEHMPfaXDnRJ){return String.fromCharCode(EyrHjUcpVpoZtuvJxeI,cyRucZEFFkfEHMPfaXDnRJ" ascii
    $s12 = "C);} while (zgXpRpZTHCFWxonaSe < FEhqwrGPZafTh.length);return SbGIrgDDenVUA;}" fullword ascii
    $s13 = ";if (xKkugvu == 64) SbGIrgDDenVUA += FZ(IqxOEBGcPcyAtjObKzBNv);else if (DfJDyurDxWfuTjnQWeMVwKm == 64) SbGIrgDDenVUA += TXbAp(Iq" ascii
    $s14 = "fu]];}return oszsHpDUwZgrMc.substring(3,oszsHpDUwZgrMc.length);}" fullword ascii
    $s15 = "(LMeWCjEZGDJJ,0x1,0x0)}function bjGcH(HqpjdGuaQArq,HNxpMpfHf,ELifNQspQCSVKJ){var IgAjnDXZxy=HqpjdGuaQArq.createtextfile(HNxpMpfH" ascii
    $s16 = "function ZlXao(FEhqwrGPZafTh) {var sNAzhah = dliUzYE.join(fAZNpUcbhfifBqL[7]);var IqxOEBGcPcyAtjObKzBNv, eRKINGNyzNqwnvwN, lxsEE" ascii
    $s17 = "var XscJa=function(){return new ActiveXObject(fAZNpUcbhfifBqL[1]);}();" fullword ascii
    $s18 = "function YnHjzrPttGGXLU(){return XEDcLVWJVg(fAZNpUcbhfifBqL[9],[1,5,7],fAZNpUcbhfifBqL[10]);}" fullword ascii
    $s19 = "function XEDcLVWJVg(NkMQBNllxh,jcPqVSyubjoIR,NaVsZzCMUYx){nVEBJovZMIwd=NkMQBNllxh.split(NaVsZzCMUYx);oszsHpDUwZgrMc = fAZNpUcbhf" ascii
    $s20 = "function CuWsIKEn(LumbJAzxpYHIOTBUvdBDngS,FQpjLDMrvgiOlMeeAV,EOeJYAxdbpvCsSHaiZ){return String.fromCharCode(LumbJAzxpYHIOTBUvdBD" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}