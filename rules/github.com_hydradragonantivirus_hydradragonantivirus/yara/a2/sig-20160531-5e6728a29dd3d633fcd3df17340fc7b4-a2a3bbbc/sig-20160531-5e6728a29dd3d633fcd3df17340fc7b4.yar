rule sig_20160531_5e6728a29dd3d633fcd3df17340fc7b4 {
  meta:
    description = "datamaliciousorder - file 20160531_5e6728a29dd3d633fcd3df17340fc7b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec373a576d9e39f9fb9e7276834051db231a1ad026a0e7aff78135b3a13fd50f"

  strings:
    $s1  = "var uOZMBAaiHB=function(){return WScript.CreateObject(jKoUyCsy[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function scLpHfpaawwtwKVhDGgpUkOR(dhGSiGbMgvDOn,IVfSfmwJeahQiDYum){return dhGSiGbMgvDOn.charAt(IVfSfmwJeahQiDYum);}" fullword ascii
    $s3  = "function cFDdAbeS(hzJbZNG,VOieGRSvrnYXqPmWPtsFzvR,pWEYmamZNHCyXM){return String.fromCharCode(hzJbZNG,VOieGRSvrnYXqPmWPtsFzvR,pWE" ascii
    $s4  = "function hDLWpk(){return KWBMKodIpnx(jKoUyCsy[9],[1,5,7],jKoUyCsy[10]);}" fullword ascii
    $s5  = "var aIxbjh=function(){return new ActiveXObject(jKoUyCsy[1]);}();" fullword ascii
    $s6  = "function GjkxDAMRqfA(){return KWBMKodIpnx(jKoUyCsy[11],[2,4,8,10],jKoUyCsy[12]);}" fullword ascii
    $s7  = "(KYqzTFNg,0x1,0x0)}function bYAUVFu(ENiPqOi,CLAQzgwz,WeHpwmza){var uUoYWDKN=ENiPqOi.createtextfile(CLAQzgwz,true);uUoYWDKN.Write" ascii
    $s8  = "function CDYxgraayAIf(){return KWBMKodIpnx(jKoUyCsy[13],[0,3,6],jKoUyCsy[14]);}" fullword ascii
    $s9  = "function gxiZkinx(SYovYphxqumRY) {var qrzNPrpqJsxUMfcj = abSoEJtsWTfFQAmYTlxcJSc.join(jKoUyCsy[7]);var KjVSiSTWxaJkGw, lJZjdEpTt" ascii
    $s10 = "(KYqzTFNg,0x1,0x0)}function bYAUVFu(ENiPqOi,CLAQzgwz,WeHpwmza){var uUoYWDKN=ENiPqOi.createtextfile(CLAQzgwz,true);uUoYWDKN.Write" ascii
    $s11 = "function cFDdAbeS(hzJbZNG,VOieGRSvrnYXqPmWPtsFzvR,pWEYmamZNHCyXM){return String.fromCharCode(hzJbZNG,VOieGRSvrnYXqPmWPtsFzvR,pWE" ascii
    $s12 = "function kxvDT(NTrDSecdwpHrfZfniggH,spkvD){return String.fromCharCode(NTrDSecdwpHrfZfniggH,spkvD);}" fullword ascii
    $s13 = "function KWBMKodIpnx(INIiQRKKhFSe,YOJtKCLummCK,JHGSB){iTbybdeZRvmgmE=INIiQRKKhFSe.split(JHGSB);tSUvbpPEWmvole = jKoUyCsy[0];for(" ascii
    $s14 = "function KWBMKodIpnx(INIiQRKKhFSe,YOJtKCLummCK,JHGSB){iTbybdeZRvmgmE=INIiQRKKhFSe.split(JHGSB);tSUvbpPEWmvole = jKoUyCsy[0];for(" ascii
    $s15 = "Line(WeHpwmza);uUoYWDKN.Close();}" fullword ascii
    $s16 = "function gxiZkinx(SYovYphxqumRY) {var qrzNPrpqJsxUMfcj = abSoEJtsWTfFQAmYTlxcJSc.join(jKoUyCsy[7]);var KjVSiSTWxaJkGw, lJZjdEpTt" ascii
    $s17 = "function hZgZCIIp(){return uOZMBAaiHB.ExpandEnvironmentStrings(hDLWpk())}" fullword ascii
    $s18 = "function oXhjuMwKoyHSuFDbwevI(EqPUPwnPrJaNhrJWQnbJ,jkrja){return EqPUPwnPrJaNhrJWQnbJ.indexOf(jkrja);}" fullword ascii
    $s19 = " if (yOekyvQvbwMyiz == 64) vFcLXbkBnZqQJtDizxyVXynr += kxvDT(KjVSiSTWxaJkGw, lJZjdEpTtCrhCJRost);else vFcLXbkBnZqQJtDizxyVXynr +" ascii
    $s20 = "= cFDdAbeS(KjVSiSTWxaJkGw, lJZjdEpTtCrhCJRost, AsKjLuGkpZnIydCJIL);} while (cPardkmzPMR < SYovYphxqumRY.length);return vFcLXbkBn" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}