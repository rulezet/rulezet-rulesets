rule sig_20160525_212ef48535208c4ef73de439f1779573 {
  meta:
    description = "datamaliciousorder - file 20160525_212ef48535208c4ef73de439f1779573.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29a441badb55ad7761db80179a75ab2071461fb140f7b3e1aa932c266c33567f"

  strings:
    $s1  = "Math.sin(45), 2) + Math.pow(Math.cos(45), 2) - 1))-814)) aZNCRcM += Sv(uaEGKlPbi);else if (PDclBVxXZwaD == (508 + Math.round((Ma" ascii
    $s2  = "nd((Math.pow(Math.sin(8), 2) + Math.pow(Math.cos(8), 2) - 1))-144) | plbiWkAJQNBCPNxoBGycMWyb<< (911 + Math.round((Math.pow(Math" ascii
    $s3  = "function kKctbZoI(lyxrWhHMUNfmo) {var yDZCHDQfKvlaAUACUoraA = dlBgoKWAXubcTKDLWikLM.join(xHuIhxJODJPJHkJWN[0]);var uaEGKlPbi, Wv" ascii
    $s4  = "function KNWZebkYTdl(LsNZaSWAaL,ylMaimEHOzmFdfWUvLfQMeV){return LsNZaSWAaL.charAt(ylMaimEHOzmFdfWUvLfQMeV);}" fullword ascii
    $s5  = "function kKctbZoI(lyxrWhHMUNfmo) {var yDZCHDQfKvlaAUACUoraA = dlBgoKWAXubcTKDLWikLM.join(xHuIhxJODJPJHkJWN[0]);var uaEGKlPbi, Wv" ascii
    $s6  = "function NtdFJdvcHCBacycsDrxTOPzg(LLvIecwQXfkgELnfLqQhtOo,gKexAqXWKZUlofyWVZGUT){return String.fromCharCode(LLvIecwQXfkgELnfLqQh" ascii
    $s7  = "ngth);return aZNCRcM;}" fullword ascii
    $s8  = "function NtdFJdvcHCBacycsDrxTOPzg(LLvIecwQXfkgELnfLqQhtOo,gKexAqXWKZUlofyWVZGUT){return String.fromCharCode(LLvIecwQXfkgELnfLqQh" ascii
    $s9  = "function Sv(PHdKl){return String.fromCharCode(PHdKl);}" fullword ascii
    $s10 = "function HEoHOdvsDGazZoPGmqFd(qcBwreWo,FkPSQLCDE){return qcBwreWo.indexOf(FkPSQLCDE);}" fullword ascii
    $s11 = "function gGVyEGOzjyHEPECPxjtG(ZPtGBpQBOHTQsYyWmPDu,yPgRirad,iOqzHM){return String.fromCharCode(ZPtGBpQBOHTQsYyWmPDu,yPgRirad,iOq" ascii
    $s12 = "function gGVyEGOzjyHEPECPxjtG(ZPtGBpQBOHTQsYyWmPDu,yPgRirad,iOqzHM){return String.fromCharCode(ZPtGBpQBOHTQsYyWmPDu,yPgRirad,iOq" ascii
    $s13 = "f);else aZNCRcM += gGVyEGOzjyHEPECPxjtG(uaEGKlPbi, WvsfHULcDjsJxVaf, JzGRucURmncrXlTccXXDHZ);} while (RgXGfRP < lyxrWhHMUNfmo.le" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}