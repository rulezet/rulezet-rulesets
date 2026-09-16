rule sig_20160527_31f19ea601405037efc42a076a328712 {
  meta:
    description = "datamaliciousorder - file 20160527_31f19ea601405037efc42a076a328712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b767e07633b2688b3ad747400b89372534d636831062149e05a6ad21fa70852"

  strings:
    $s1  = "function wIrYPPX() {return WScript;}function gMdBUSjgi(){return ILZRlDmPN.ExpandEnvironmentStrings(ApiTqlCN())}" fullword ascii
    $s2  = "function CRTyNTtjcqYwNUmnvGy(wtcpdKVQatD,dfYXTCtX){return wtcpdKVQatD.charAt(dfYXTCtX);}" fullword ascii
    $s3  = "function dIrdMPpCOdECV(oUxTwtGiHhL,vAqCM) {var SXZFJB=[XahCxEM[15]];oUxTwtGiHhL[SXZFJB[0]](vAqCM,0x1,0x0)}" fullword ascii
    $s4  = "WHlfU, CYEzxxd, lGjjepMXWNeWaeIF);} while (aofgZfwiHzir < GEYDscKXIzGWq.length);return PbFySquQ;}" fullword ascii
    $s5  = "function wYmfKEvHMuoNTLcRtZfT(ekAOoSU,SPbfdiLtglCtQOFnBX){return String.fromCharCode(ekAOoSU,SPbfdiLtglCtQOFnBX);}" fullword ascii
    $s6  = "function UhFeYJhZLuDcOk(mtLfjoVHzwYqFd,LcfFPyGOSRzlLC,NYjSE){return String.fromCharCode(mtLfjoVHzwYqFd,LcfFPyGOSRzlLC,NYjSE);}" fullword ascii
    $s7  = "function CiQLZaYGsUKMKaHt(CGHHqsrOxTDkCpXOmyZrco,rNWebnsDy){return CGHHqsrOxTDkCpXOmyZrco.indexOf(rNWebnsDy);}" fullword ascii
    $s8  = "function AU(AHZkpmQBcyhQRdddVWmbi){return String.fromCharCode(AHZkpmQBcyhQRdddVWmbi);}" fullword ascii
    $s9  = "var ILZRlDmPN=function(){return wIrYPPX().CreateObject(XahCxEM[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function OYmLDF(){return vBPNBDJlw(XahCxEM[10],[2,4,8,10],XahCxEM[11]);}" fullword ascii
    $s11 = "function ApiTqlCN(){return vBPNBDJlw(XahCxEM[8],[1,5,7],XahCxEM[9]);}" fullword ascii
    $s12 = "HofnhA<GFkCDjDK.length;ZlnpYxHofnhA++) {bWXyYYzeBHsv+=tWWbVKa[GFkCDjDK[ZlnpYxHofnhA]];}return bWXyYYzeBHsv.substring(3,bWXyYYzeB" ascii
    $s13 = "var YfJbcEUomqtVyT=function(){return new ActiveXObject(XahCxEM[0]);}();" fullword ascii
    $s14 = "var VjdoT = YfJbcEUomqtVyT.createtextfile(ILZRlDmPN.ExpandEnvironmentStrings(XahCxEM[2]+XahCxEM[3])+String.fromCharCode(92)+XahC" ascii
    $s15 = "function SPobl(GEYDscKXIzGWq) {var zqSNvlobijemUso = kpMukCnDbfvDsJLeIBaK.join(XahCxEM[6]);var hYDqByBONdWHlfU, CYEzxxd, lGjjepM" ascii
    $s16 = "se if (VGQiHKrxbteX == 64) PbFySquQ += wYmfKEvHMuoNTLcRtZfT(hYDqByBONdWHlfU, CYEzxxd);else PbFySquQ += UhFeYJhZLuDcOk(hYDqByBONd" ascii
    $s17 = "function SPobl(GEYDscKXIzGWq) {var zqSNvlobijemUso = kpMukCnDbfvDsJLeIBaK.join(XahCxEM[6]);var hYDqByBONdWHlfU, CYEzxxd, lGjjepM" ascii
    $s18 = "function RLXcvsV(){return vBPNBDJlw(XahCxEM[12],[0,3,6],XahCxEM[13]);}" fullword ascii
    $s19 = "function vBPNBDJlw(XGFNsAy,GFkCDjDK,RwKXoLc){tWWbVKa=XGFNsAy.split(RwKXoLc);bWXyYYzeBHsv = XahCxEM[14];for(ZlnpYxHofnhA=0;ZlnpYx" ascii
    $s20 = "function vBPNBDJlw(XGFNsAy,GFkCDjDK,RwKXoLc){tWWbVKa=XGFNsAy.split(RwKXoLc);bWXyYYzeBHsv = XahCxEM[14];for(ZlnpYxHofnhA=0;ZlnpYx" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}