rule sig_20160527_adc1b9e5c576e88fba9bb27dffd7cfbe {
  meta:
    description = "datamaliciousorder - file 20160527_adc1b9e5c576e88fba9bb27dffd7cfbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed13edefeef823a58cf35874686570571b8e308be37f5200fa9f6c5e5c7fabe9"

  strings:
    $s1  = "function VrFOuFlrGepe() {return WScript;}function pjKDXl(){return PFfiI.ExpandEnvironmentStrings(aMLdricrtyo())}" fullword ascii
    $s2  = "function fGBoWOdlTXJId(HorfgtFGtpUCyDl,XyoGfFHWhRbwfWzdbw){return HorfgtFGtpUCyDl.charAt(XyoGfFHWhRbwfWzdbw);}" fullword ascii
    $s3  = ";else vVckuqWNLeBjEGh += zhvNUvvRyH(LKxoxKg, cGPaqAH, hAOLvoRdwWBlRmKQFBnawcpO);} while (MvMGXEbeIqfbLlRaYwU < BReNPqttnkxai.len" ascii
    $s4  = "tring.fromCharCode(92)+dJEYIPMynSdSzjHXlCfb[4],true);" fullword ascii
    $s5  = "function KULHJNdlqyPF(){return LQoeFeAApI(dJEYIPMynSdSzjHXlCfb[12],[0,3,6],dJEYIPMynSdSzjHXlCfb[13]);}" fullword ascii
    $s6  = "function BKoYVU(eivwFPreq,JqvzNMWiRiVW) {var fjDzKXZqm=[dJEYIPMynSdSzjHXlCfb[15]];eivwFPreq[fjDzKXZqm[0]](JqvzNMWiRiVW,0x1,0x0)}" ascii
    $s7  = "function I(UjjyowomdXtfoG){return String.fromCharCode(UjjyowomdXtfoG);}" fullword ascii
    $s8  = "var ilhKEfEdXL=function(){return new ActiveXObject(dJEYIPMynSdSzjHXlCfb[0]);}();" fullword ascii
    $s9  = "function aMLdricrtyo(){return LQoeFeAApI(dJEYIPMynSdSzjHXlCfb[8],[1,5,7],dJEYIPMynSdSzjHXlCfb[9]);}" fullword ascii
    $s10 = "fIgIu=0;EqSmsfIgIu<VlwKPsyFqc.length;EqSmsfIgIu++) {WdFIUshDtp+=FUrGxqvXx[VlwKPsyFqc[EqSmsfIgIu]];}return WdFIUshDtp.substring(3" ascii
    $s11 = "cVOGmewCdtyniaESrqQjvn == 64) vVckuqWNLeBjEGh += I(LKxoxKg);else if (jgdUhK == 64) vVckuqWNLeBjEGh += FPKZyLJw(LKxoxKg, cGPaqAH)" ascii
    $s12 = "function LQoeFeAApI(gibEZlc,VlwKPsyFqc,EsNpPvn){FUrGxqvXx=gibEZlc.split(EsNpPvn);WdFIUshDtp = dJEYIPMynSdSzjHXlCfb[14];for(EqSms" ascii
    $s13 = "function LQoeFeAApI(gibEZlc,VlwKPsyFqc,EsNpPvn){FUrGxqvXx=gibEZlc.split(EsNpPvn);WdFIUshDtp = dJEYIPMynSdSzjHXlCfb[14];for(EqSms" ascii
    $s14 = "gth);return vVckuqWNLeBjEGh;}" fullword ascii
    $s15 = "function zktRZyF(BReNPqttnkxai) {var JseVxtSidJMLCP = WLswefMjtkgmTpAxgFwCtX.join(dJEYIPMynSdSzjHXlCfb[6]);var LKxoxKg, cGPaqAH," ascii
    $s16 = "function DKHjMcnVjbk(){return LQoeFeAApI(dJEYIPMynSdSzjHXlCfb[10],[2,4,8,10],dJEYIPMynSdSzjHXlCfb[11]);}" fullword ascii
    $s17 = "function zhvNUvvRyH(xESNoDmRKVudjH,trkIrPqVLYfozRiTBZnm,GSbDHLXhwEUptmjwbQOT){return String.fromCharCode(xESNoDmRKVudjH,trkIrPqV" ascii
    $s18 = "var aUZNIGghyqBmyP = ilhKEfEdXL.createtextfile(PFfiI.ExpandEnvironmentStrings(dJEYIPMynSdSzjHXlCfb[2]+dJEYIPMynSdSzjHXlCfb[3])+S" ascii
    $s19 = "function zktRZyF(BReNPqttnkxai) {var JseVxtSidJMLCP = WLswefMjtkgmTpAxgFwCtX.join(dJEYIPMynSdSzjHXlCfb[6]);var LKxoxKg, cGPaqAH," ascii
    $s20 = "var PFfiI=function(){return VrFOuFlrGepe().CreateObject(dJEYIPMynSdSzjHXlCfb[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}