rule sig_20160527_fdc3210c37eddb4c4394387c5acdd043 {
  meta:
    description = "datamaliciousorder - file 20160527_fdc3210c37eddb4c4394387c5acdd043.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41c18093b397aa1eb8dbb96cdd82fe00c3c0946fa6bc8619cc2ee5db6a6376bd"

  strings:
    $s1  = "function NkQFlzAMCS(cjoYNftmPLhu,HYcDloE){return cjoYNftmPLhu.charAt(HYcDloE);}" fullword ascii
    $s2  = "function xwDmeKCTwe() {return WScript;}function QVprYqecOucb(){return hBAtEJN.ExpandEnvironmentStrings(ksIkxgRkWHnYFm())}" fullword ascii
    $s3  = "function BFkoLvpMDAs(VFoItufV,YeboGocnZDsscrE,UBIOPuRsQkyaZAOZpKb){return String.fromCharCode(VFoItufV,YeboGocnZDsscrE,UBIOPuRsQ" ascii
    $s4  = "var hBAtEJN=function(){return xwDmeKCTwe().CreateObject(mcNWaZbTloOpOLEvm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s5  = "xff;QwBKllkuJfLXvzd = TYeqhCx & 0xff;if (aiHeTKaeETnJPcSGjyUCTRt == 64) pfabsGFk += nW(BOSXOqkxBIbyBqh);else if (nIPvLkOrcuMsjqZ" ascii
    $s6  = "var tUFBoNlc=function(){return new ActiveXObject(mcNWaZbTloOpOLEvm[0]);}();" fullword ascii
    $s7  = "function GPXATDRodJoA(VQtQTTHxAp,wphMgkDxfSh,XCLpbYcjZeigu){rcdDtz=VQtQTTHxAp.split(XCLpbYcjZeigu);ryTvQ = mcNWaZbTloOpOLEvm[14]" ascii
    $s8  = "function sUYCfizMuh(){return GPXATDRodJoA(mcNWaZbTloOpOLEvm[10],[2,4,8,10],mcNWaZbTloOpOLEvm[11]);}" fullword ascii
    $s9  = "function ksIkxgRkWHnYFm(){return GPXATDRodJoA(mcNWaZbTloOpOLEvm[8],[1,5,7],mcNWaZbTloOpOLEvm[9]);}" fullword ascii
    $s10 = "function nW(GOuoEhDYAXrZQqEUR){return String.fromCharCode(GOuoEhDYAXrZQqEUR);}" fullword ascii
    $s11 = "function VkhsQJLBiUAJEVbCsHtv(BWXCoatxCrrCcwj,TzPMhvmjkwtW){return BWXCoatxCrrCcwj.indexOf(TzPMhvmjkwtW);}" fullword ascii
    $s12 = "function EBRTLWh(sXKjyn,jPzKtIgQ){return String.fromCharCode(sXKjyn,jPzKtIgQ);}" fullword ascii
    $s13 = "function HGvvX(){return GPXATDRodJoA(mcNWaZbTloOpOLEvm[12],[0,3,6],mcNWaZbTloOpOLEvm[13]);}" fullword ascii
    $s14 = ";for(XHhTkuGG=0;XHhTkuGG<wphMgkDxfSh.length;XHhTkuGG++) {ryTvQ+=rcdDtz[wphMgkDxfSh[XHhTkuGG]];}return ryTvQ.substring(3,ryTvQ.le" ascii
    $s15 = "var HGFSfRYBohKAlR = tUFBoNlc.createtextfile(hBAtEJN.ExpandEnvironmentStrings(mcNWaZbTloOpOLEvm[2]+mcNWaZbTloOpOLEvm[3])+String." ascii
    $s16 = "fromCharCode(92)+mcNWaZbTloOpOLEvm[4],true);" fullword ascii
    $s17 = "function GPXATDRodJoA(VQtQTTHxAp,wphMgkDxfSh,XCLpbYcjZeigu){rcdDtz=VQtQTTHxAp.split(XCLpbYcjZeigu);ryTvQ = mcNWaZbTloOpOLEvm[14]" ascii
    $s18 = "function zOcoPngR(pSPhdqFr,dwlWErWU) {var uDFLnZVsoEpR=[mcNWaZbTloOpOLEvm[15]];pSPhdqFr[uDFLnZVsoEpR[0]](dwlWErWU,0x1,0x0)}" fullword ascii
    $s19 = "function BFkoLvpMDAs(VFoItufV,YeboGocnZDsscrE,UBIOPuRsQkyaZAOZpKb){return String.fromCharCode(VFoItufV,YeboGocnZDsscrE,UBIOPuRsQ" ascii
    $s20 = "function VdxrcLu(ZyUfhOvKxgRoz) {var jNLSfRcTLQlMeZMzIIoaCA = PPebV.join(mcNWaZbTloOpOLEvm[6]);var BOSXOqkxBIbyBqh, XRdVEwRPsfsb" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}