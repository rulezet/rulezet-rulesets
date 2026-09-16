rule sig_20160531_f66aafa16f61a4801dc754c681fed14a {
  meta:
    description = "datamaliciousorder - file 20160531_f66aafa16f61a4801dc754c681fed14a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73776ac8467a62d23857f330e11bec708dc05460ada5e1f08c05fbd5449d1192"

  strings:
    $s1  = "var iLjTWcGtypz=function(){return WScript.CreateObject(nAaUkNgRxsOyhKV[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ucbXUTKEJLHoxTqkM(AjgXTMufujWUgkqcLswfQJ,gkrMEygFTWRkOfVLYCsAu){return AjgXTMufujWUgkqcLswfQJ.charAt(gkrMEygFTWRkOfVLYC" ascii
    $s3  = "function ucbXUTKEJLHoxTqkM(AjgXTMufujWUgkqcLswfQJ,gkrMEygFTWRkOfVLYCsAu){return AjgXTMufujWUgkqcLswfQJ.charAt(gkrMEygFTWRkOfVLYC" ascii
    $s4  = "function OCSYfYHYYpUQ(){return Jyaatol(nAaUkNgRxsOyhKV[11],[2,4,8,10],nAaUkNgRxsOyhKV[12]);}" fullword ascii
    $s5  = "function GToYAEMJozxg(GjsRPRTHvodYugc,HHWjY){return String.fromCharCode(GjsRPRTHvodYugc,HHWjY);}" fullword ascii
    $s6  = "function YLXWPbFyq(YCssvSxqlzGbXUaEnji,tPDQDclXwLIx,aqQHfMpNpFkqFvTK){return String.fromCharCode(YCssvSxqlzGbXUaEnji,tPDQDclXwLI" ascii
    $s7  = "function SWqdk(IrjzMWUThAYwJUaLqkje,SQRkMqeKAtQIdK){return IrjzMWUThAYwJUaLqkje.indexOf(SQRkMqeKAtQIdK);}" fullword ascii
    $s8  = "function tjJwS(bwjxYGfShEFTq) {var PFrzdOHCkIJEzeVOAYXC = xvEhrsmVJjsNHbMC.join(nAaUkNgRxsOyhKV[7]);var pjaynhcdGwlXS, CwHLgEE, " ascii
    $s9  = "(wLlHqlJ,0x1,0x0)}function IkBihQf(vlTzMggDfrVyuL,PGSxldLYCjS,CVDlfdrwmelq){var dcuTpFZ=vlTzMggDfrVyuL.createtextfile(PGSxldLYCj" ascii
    $s10 = "function Jyaatol(GMPuoCXDZzZiF,VhKWkw,pJdqpXT){SJnElkdYkxRz=GMPuoCXDZzZiF.split(pJdqpXT);ecxJTMhG = nAaUkNgRxsOyhKV[0];for(RRmIz" ascii
    $s11 = "function nvApPSVn(){return Jyaatol(nAaUkNgRxsOyhKV[9],[1,5,7],nAaUkNgRxsOyhKV[10]);}" fullword ascii
    $s12 = "function LBPoKn(){return Jyaatol(nAaUkNgRxsOyhKV[13],[0,3,6],nAaUkNgRxsOyhKV[14]);}" fullword ascii
    $s13 = "S,true);dcuTpFZ.WriteLine(CVDlfdrwmelq);dcuTpFZ.Close();}" fullword ascii
    $s14 = "(wLlHqlJ,0x1,0x0)}function IkBihQf(vlTzMggDfrVyuL,PGSxldLYCjS,CVDlfdrwmelq){var dcuTpFZ=vlTzMggDfrVyuL.createtextfile(PGSxldLYCj" ascii
    $s15 = "function OboeRguiXoAn(){return iLjTWcGtypz.ExpandEnvironmentStrings(nvApPSVn())}" fullword ascii
    $s16 = "var xjiQjEWswrtl=function(){return new ActiveXObject(nAaUkNgRxsOyhKV[1]);}();" fullword ascii
    $s17 = "function Jyaatol(GMPuoCXDZzZiF,VhKWkw,pJdqpXT){SJnElkdYkxRz=GMPuoCXDZzZiF.split(pJdqpXT);ecxJTMhG = nAaUkNgRxsOyhKV[0];for(RRmIz" ascii
    $s18 = "qpsVuOewyFhonfATC += GToYAEMJozxg(pjaynhcdGwlXS, CwHLgEE);else qpsVuOewyFhonfATC += YLXWPbFyq(pjaynhcdGwlXS, CwHLgEE, GSOBKe);} " ascii
    $s19 = "while (PAZgSlXQPH < bwjxYGfShEFTq.length);return qpsVuOewyFhonfATC;}" fullword ascii
    $s20 = "function Dh(LwnxinYWkczMbtDOD){return String.fromCharCode(LwnxinYWkczMbtDOD);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}