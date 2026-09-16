rule sig_20160527_7f52d1a66108d5cbb0efd947e41233dd {
  meta:
    description = "datamaliciousorder - file 20160527_7f52d1a66108d5cbb0efd947e41233dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7e369fa36eb2d78a970b2a259748b3f4bc1d8c65a4acb0d3a786a225148ebb3"

  strings:
    $s1  = "function qWQdi() {return WScript;}function fBHIjEmeBMqO(){return PRtvrjbPnpnSkB.ExpandEnvironmentStrings(YSAUeDjZ())}" fullword ascii
    $s2  = "function hJpYxtBRTyawOKZUwVTcddjL(dnDDNkKlXKHfuyoj,lziNsRSLbERaLGUmTQmRAyIY){return dnDDNkKlXKHfuyoj.charAt(lziNsRSLbERaLGUmTQmR" ascii
    $s3  = "function hJpYxtBRTyawOKZUwVTcddjL(dnDDNkKlXKHfuyoj,lziNsRSLbERaLGUmTQmRAyIY){return dnDDNkKlXKHfuyoj.charAt(lziNsRSLbERaLGUmTQmR" ascii
    $s4  = "function CoAmcVx(TtRJlWLsU,NskXwLYSVPzcppzRvoI){return String.fromCharCode(TtRJlWLsU,NskXwLYSVPzcppzRvoI);}" fullword ascii
    $s5  = "function jdAWfPfPxLRbXVGnZq(EPnyYOkRzDJDlVRJYF,HNBVGzCFwLfrPuLCmAxcehQz){return EPnyYOkRzDJDlVRJYF.indexOf(HNBVGzCFwLfrPuLCmAxce" ascii
    $s6  = "JvAoF<NEzmANlY.length;nANJJvAoF++) {cRNBiu+=bRAUUvybnWlCS[NEzmANlY[nANJJvAoF]];}return cRNBiu.substring(3,cRNBiu.length);}" fullword ascii
    $s7  = "length);return vtKCVBgNxOXrfEQm;}" fullword ascii
    $s8  = "function sV(JYVXOoBbrJtpJYgsp){return String.fromCharCode(JYVXOoBbrJtpJYgsp);}" fullword ascii
    $s9  = "function jdAWfPfPxLRbXVGnZq(EPnyYOkRzDJDlVRJYF,HNBVGzCFwLfrPuLCmAxcehQz){return EPnyYOkRzDJDlVRJYF.indexOf(HNBVGzCFwLfrPuLCmAxce" ascii
    $s10 = "function UnTISHAXLyirGOoMpagaR(TILEQvMaqO,uuXIlZLY,rhtSLzODDHL){return String.fromCharCode(TILEQvMaqO,uuXIlZLY,rhtSLzODDHL);}" fullword ascii
    $s11 = "function UQqgLEQOnzSE(jWTAWxyCvQhea) {var jWmKUrCHKnKnYzLSWhnhmhEB = yJgvTZbFktJGIEIaDAAtCmE.join(JajMSxizkcAp[6]);var CAMePshob" ascii
    $s12 = "ZFIzgSVQvNmLz == 64) vtKCVBgNxOXrfEQm += sV(CAMePshoblisn);else if (tNVXONnnnmwxkW == 64) vtKCVBgNxOXrfEQm += CoAmcVx(CAMePshobl" ascii
    $s13 = "ode(92)+JajMSxizkcAp[4],true);" fullword ascii
    $s14 = "var PRtvrjbPnpnSkB=function(){return qWQdi().CreateObject(JajMSxizkcAp[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s15 = "function qnerrUdiY(){return Nnhdwwl(JajMSxizkcAp[12],[0,3,6],JajMSxizkcAp[13]);}" fullword ascii
    $s16 = "function Nnhdwwl(iGBWfvV,NEzmANlY,xCdVzbJf){bRAUUvybnWlCS=iGBWfvV.split(xCdVzbJf);cRNBiu = JajMSxizkcAp[14];for(nANJJvAoF=0;nANJ" ascii
    $s17 = "function IpgJQQ(IfoUDTN,bIJXeoFiXLs) {var nYzIgYedPwAhYb=[JajMSxizkcAp[15]];IfoUDTN[nYzIgYedPwAhYb[0]](bIJXeoFiXLs,0x1,0x0)}" fullword ascii
    $s18 = "function UQqgLEQOnzSE(jWTAWxyCvQhea) {var jWmKUrCHKnKnYzLSWhnhmhEB = yJgvTZbFktJGIEIaDAAtCmE.join(JajMSxizkcAp[6]);var CAMePshob" ascii
    $s19 = "function Nnhdwwl(iGBWfvV,NEzmANlY,xCdVzbJf){bRAUUvybnWlCS=iGBWfvV.split(xCdVzbJf);cRNBiu = JajMSxizkcAp[14];for(nANJJvAoF=0;nANJ" ascii
    $s20 = "isn, oilIzCa);else vtKCVBgNxOXrfEQm += UnTISHAXLyirGOoMpagaR(CAMePshoblisn, oilIzCa, gFuSBcLwPM);} while (xYVzK < jWTAWxyCvQhea." ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}