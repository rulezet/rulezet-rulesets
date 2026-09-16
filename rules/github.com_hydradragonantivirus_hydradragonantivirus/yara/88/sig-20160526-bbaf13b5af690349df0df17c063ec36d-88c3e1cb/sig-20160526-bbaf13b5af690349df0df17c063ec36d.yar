rule sig_20160526_bbaf13b5af690349df0df17c063ec36d {
  meta:
    description = "datamaliciousorder - file 20160526_bbaf13b5af690349df0df17c063ec36d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "812b65b417ad89274dc4a361de32ef81619df3fd51000601247ccad252b71d21"

  strings:
    $s1  = "(Math.pow(Math.sin(598), 2) + Math.pow(Math.cos(598), 2) - 1))-414)) OMNOhzNSUc += o(bsGgWjAzTGjVh);else if (NPOxFrPDOUavTaQAnJ " ascii
    $s2  = "function rpuGivjx(YninKjtXNVfiM) {var MBTGAqqtVEcNERslLXDOQmV = NrHxJxMmJMwN.join(zjZkjOlmPYEYJ[0]);var bsGgWjAzTGjVh, XgDsFPMNb" ascii
    $s3  = "function IawDAg(ChuMCMIVeoUfukliOarF,zhUQDkiWoQCYCQeA){return ChuMCMIVeoUfukliOarF.charAt(zhUQDkiWoQCYCQeA);}" fullword ascii
    $s4  = "function jTyXQDcMxwOsVvwYjpJc(wZSvopXcpHqXgsOuN,JwfLyIwkaShoMeX,paoqA){return String.fromCharCode(wZSvopXcpHqXgsOuN,JwfLyIwkaSho" ascii
    $s5  = "h, XgDsFPMNbic);else OMNOhzNSUc += jTyXQDcMxwOsVvwYjpJc(bsGgWjAzTGjVh, XgDsFPMNbic, kYtksGJZpnAfUxLl);} while (PogGnMbWlxArSWruk" ascii
    $s6  = " < YninKjtXNVfiM.length);return OMNOhzNSUc;}" fullword ascii
    $s7  = "function SFkInauaOOMQHmqsZDjdg(omgnhOrXBGQCqkEM,cDwDdKN){return omgnhOrXBGQCqkEM.indexOf(cDwDdKN);}" fullword ascii
    $s8  = "function jTyXQDcMxwOsVvwYjpJc(wZSvopXcpHqXgsOuN,JwfLyIwkaShoMeX,paoqA){return String.fromCharCode(wZSvopXcpHqXgsOuN,JwfLyIwkaSho" ascii
    $s9  = "function YsuqNkjzZpt(cVeNxivkNfItaLCRnmU,CRTdfRmID){return String.fromCharCode(cVeNxivkNfItaLCRnmU,CRTdfRmID);}" fullword ascii
    $s10 = "function o(McTCZbKYLp){return String.fromCharCode(McTCZbKYLp);}" fullword ascii
    $s11 = "function rpuGivjx(YninKjtXNVfiM) {var MBTGAqqtVEcNERslLXDOQmV = NrHxJxMmJMwN.join(zjZkjOlmPYEYJ[0]);var bsGgWjAzTGjVh, XgDsFPMNb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}