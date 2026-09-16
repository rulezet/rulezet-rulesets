rule sig_20160531_8f46ba97c8049010c8111e85cc0e972c {
  meta:
    description = "datamaliciousorder - file 20160531_8f46ba97c8049010c8111e85cc0e972c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "266a009185766489afec9e4b17aab21a539343c8a0601a6968164d1e8d9e88f9"

  strings:
    $s1  = "var msiknv=function(){return WScript.CreateObject(XRgrtrRNQ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function SKYlGxBMHwDkXAHy(qTbMwLGvhyDGUjB,YAgujlWRExohStdrlQFmZUi){return qTbMwLGvhyDGUjB.charAt(YAgujlWRExohStdrlQFmZUi);}" fullword ascii
    $s3  = "IEYIMOgPZYYkJpHLBX, HhmEliHQxJHA, KONgDAQGJGSGBNauB);} while (YugZCUczCmDccKSqrK < ViLYXfmQwVBNi.length);return uKApnwspNWMMIfVn" ascii
    $s4  = "function FqhVnxWKCQ(fbFaIGo,PnJeXQlggJ,IHwOUxrvHqqzMi){TFWMticVwFZ=fbFaIGo.split(IHwOUxrvHqqzMi);FkjasKYvNrNFt = XRgrtrRNQ[0];fo" ascii
    $s5  = "(WRBZjMKjCfjnc,0x1,0x0)}function yiMrjDRcxkmHdK(HbbgMxAIy,PMLDNJoZNPX,apSHL){var uHvDJHXxouddyp=HbbgMxAIy.createtextfile(PMLDNJo" ascii
    $s6  = "var jHfQyTAfTNXVuI=function(){return new ActiveXObject(XRgrtrRNQ[1]);}();" fullword ascii
    $s7  = "function EXPzdeGEJrWJ(){return msiknv.ExpandEnvironmentStrings(oPXGQHf())}" fullword ascii
    $s8  = "ZNPX,true);uHvDJHXxouddyp.WriteLine(apSHL);uHvDJHXxouddyp.Close();}" fullword ascii
    $s9  = "function tOmYkF(){return FqhVnxWKCQ(XRgrtrRNQ[13],[0,3,6],XRgrtrRNQ[14]);}" fullword ascii
    $s10 = "function yVghEkmusXQrBKKdr(AdBuYuYdzHhqwHwiOiXUr,cKZCzodpQlyTGEesw){return AdBuYuYdzHhqwHwiOiXUr.indexOf(cKZCzodpQlyTGEesw);}" fullword ascii
    $s11 = "function GcHsFQAvYtQ(IApRFEkCKRugVUrvw,GPoSDvhHbFcOVNWONrIUbueI){return String.fromCharCode(IApRFEkCKRugVUrvw,GPoSDvhHbFcOVNWONr" ascii
    $s12 = "function US(txApsTlIUTrBjwRKQ){return String.fromCharCode(txApsTlIUTrBjwRKQ);}" fullword ascii
    $s13 = "function WSlDnoioyUmyw(nfeYFSZUSouvRRMBR,unFiAs,aJmNBjOPsArIn){return String.fromCharCode(nfeYFSZUSouvRRMBR,unFiAs,aJmNBjOPsArIn" ascii
    $s14 = "Ebudx == 64) uKApnwspNWMMIfVnFIyJS += GcHsFQAvYtQ(IEYIMOgPZYYkJpHLBX, HhmEliHQxJHA);else uKApnwspNWMMIfVnFIyJS += WSlDnoioyUmyw(" ascii
    $s15 = "r(RWsDgWFLKzVj=0;RWsDgWFLKzVj<PnJeXQlggJ.length;RWsDgWFLKzVj++) {FkjasKYvNrNFt+=TFWMticVwFZ[PnJeXQlggJ[RWsDgWFLKzVj]];}return Fk" ascii
    $s16 = "function GcHsFQAvYtQ(IApRFEkCKRugVUrvw,GPoSDvhHbFcOVNWONrIUbueI){return String.fromCharCode(IApRFEkCKRugVUrvw,GPoSDvhHbFcOVNWONr" ascii
    $s17 = "function WSlDnoioyUmyw(nfeYFSZUSouvRRMBR,unFiAs,aJmNBjOPsArIn){return String.fromCharCode(nfeYFSZUSouvRRMBR,unFiAs,aJmNBjOPsArIn" ascii
    $s18 = "(WRBZjMKjCfjnc,0x1,0x0)}function yiMrjDRcxkmHdK(HbbgMxAIy,PMLDNJoZNPX,apSHL){var uHvDJHXxouddyp=HbbgMxAIy.createtextfile(PMLDNJo" ascii
    $s19 = "function KciGCqvp(ViLYXfmQwVBNi) {var IgiUc = HiamBWxczlvbqZTf.join(XRgrtrRNQ[7]);var IEYIMOgPZYYkJpHLBX, HhmEliHQxJHA, KONgDAQG" ascii
    $s20 = "function NqOGAXdrJOeih(){return FqhVnxWKCQ(XRgrtrRNQ[11],[2,4,8,10],XRgrtrRNQ[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}