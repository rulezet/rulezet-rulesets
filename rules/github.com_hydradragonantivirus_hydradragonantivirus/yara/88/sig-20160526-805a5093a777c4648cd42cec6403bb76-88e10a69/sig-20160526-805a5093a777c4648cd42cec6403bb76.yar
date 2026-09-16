rule sig_20160526_805a5093a777c4648cd42cec6403bb76 {
  meta:
    description = "datamaliciousorder - file 20160526_805a5093a777c4648cd42cec6403bb76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33a43a75847ce07b6e55b8dcf905a2d43f49f67f59631b60da1ee03e35e129df"

  strings:
    $s1  = "Math.pow(Math.sin(207), 2) + Math.pow(Math.cos(207), 2) - 1))-204)) HyPHELhT += Gc(awXXJLbHQaHcThCp);else if (yLhJazX == (795 + " ascii
    $s2  = "round((Math.pow(Math.sin(269), 2) + Math.pow(Math.cos(269), 2) - 1))-837) | oZxtvugcqt<< (67 + Math.round((Math.pow(Math.sin(398" ascii
    $s3  = "function kJzDTFHEQyuiu(RxGlLdqCGcoMe) {var iTFvKVCeZUrzkGX = yJBQdiZUZQupQrlNJfeZU.join(ASSLlnvtsjlBQTa[0]);var awXXJLbHQaHcThCp" ascii
    $s4  = "CADDNbVkfIYxxoLld<< (175 + Math.round((Math.pow(Math.sin(735), 2) + Math.pow(Math.cos(735), 2) - 1))-157) | uhQxP<< (849 + Math." ascii
    $s5  = "function DachS(zeoOuSGVleGpqh,DXYWezUKyiXhNkISzBfLYsTG){return zeoOuSGVleGpqh.charAt(DXYWezUKyiXhNkISzBfLYsTG);}" fullword ascii
    $s6  = "D < RxGlLdqCGcoMe.length);return HyPHELhT;}" fullword ascii
    $s7  = "function kJzDTFHEQyuiu(RxGlLdqCGcoMe) {var iTFvKVCeZUrzkGX = yJBQdiZUZQupQrlNJfeZU.join(ASSLlnvtsjlBQTa[0]);var awXXJLbHQaHcThCp" ascii
    $s8  = "function Gc(yhRVAXBVSihATRMQywzcY){return String.fromCharCode(yhRVAXBVSihATRMQywzcY);}" fullword ascii
    $s9  = "function TgwbaserfsdGlqK(WJaRxzodFy,uMFoxvjOiqKRhDbwNMDu){return String.fromCharCode(WJaRxzodFy,uMFoxvjOiqKRhDbwNMDu);}" fullword ascii
    $s10 = "function ojsTrfSFnamFDlGItuCyiXcM(PeMhQ,EKPeEO){return PeMhQ.indexOf(EKPeEO);}" fullword ascii
    $s11 = "function ldiYKkHDMvnoxpxKg(MCxMCDrAX,pdgTZxsUsYWqBdqn,wdFQo){return String.fromCharCode(MCxMCDrAX,pdgTZxsUsYWqBdqn,wdFQo);}" fullword ascii
    $s12 = "LicQqAHXAfgQgtE);else HyPHELhT += ldiYKkHDMvnoxpxKg(awXXJLbHQaHcThCp, byLicQqAHXAfgQgtE, jSERtPxWpeEStAhMUkRTsod);} while (jSnIQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}