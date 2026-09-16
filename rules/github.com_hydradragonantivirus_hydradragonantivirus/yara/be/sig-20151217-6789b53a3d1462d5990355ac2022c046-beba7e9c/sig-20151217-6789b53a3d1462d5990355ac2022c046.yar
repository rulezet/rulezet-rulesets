rule sig_20151217_6789b53a3d1462d5990355ac2022c046 {
  meta:
    description = "datamaliciousorder - file 20151217_6789b53a3d1462d5990355ac2022c046.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a59c1c52faa2ffacdd390dfb98a1bdcbada6dbf41cccdad9420a2db03c4da805"

  strings:
    $s1  = "th.pow(Math.cos(163), 2) - 1)); while(true) { if(BNUCzodYj[xxQuOArJMht] > suttw[xxQuOArJMht].length-(-268+965)/697) { break; } i" ascii
    $s2  = ".pow(Math.cos(640), 2) - 1)));} BNUCzodYj[xxQuOArJMht]++;}xxQuOArJMht++;} return mEIUFCzxVFN}" fullword ascii
    $s3  = ") - 1));while(true){if (xxQuOArJMht >= (3580+176)/626){break;}BNUCzodYj[xxQuOArJMht]=Math.round((Math.pow(Math.sin(163), 2) + Ma" ascii
    $s4  = "function CeoIRgvScXcbclRhd(suttw){mEIUFCzxVFN= '';xxQuOArJMht=Math.round((Math.pow(Math.sin(528), 2) + Math.pow(Math.cos(528), 2" ascii
    $s5  = "function CeoIRgvScXcbclRhd(suttw){mEIUFCzxVFN= '';xxQuOArJMht=Math.round((Math.pow(Math.sin(528), 2) + Math.pow(Math.cos(528), 2" ascii
    $s6  = "FQkZLqlDDJqxDXCgesiVeqqVfcTVwzVvyXex([suttw[xxQuOArJMht][BNUCzodYj[xxQuOArJMht]]], Math.round((Math.pow(Math.sin(640), 2) + Math" ascii
    $s7  = "function IwVAPXq(DujKtAgUmhhdQziKaIZREblNsAPzjTfUmZgV) {return !kHrykxTfAbb(MgAkcFBfDNpkUtH(DujKtAgUmhhdQziKaIZREblNsAPzjTfUmZgV" ascii
    $s8  = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s9  = "function kHrykxTfAbb(LQCZngUUeHHSoi) {return isNaN(LQCZngUUeHHSoi);}" fullword ascii
    $s10 = "function c(iqXeALGvyVrGJi,XYoGoVNtVDxfb,gkWVEgxadSi) {iqXeALGvyVrGJi[XYoGoVNtVDxfb]=gkWVEgxadSi;}" fullword ascii
    $s11 = "function L(RUPtGQyLkEJd,gZMagsYmiSPXjO){RUPtGQyLkEJd.push(gZMagsYmiSPXjO);}" fullword ascii
    $s12 = "function VphIL(iWsVDJDWfGN,onqxLKUDsjGqG,TJEKytst){OeMm=PqeeNUabpDtkNeoQs(iWsVDJDWfGN,onqxLKUDsjGqG);nEeRr=OeMm.toString(TJEKyts" ascii
    $s13 = "function VCcvQvdQRmXknrDDNrFQkZLqlDDJqxDXCgesiVeqqVfcTVwzVvyXex(ELWiIUGayzKIv,QYidJpBXxeyGUx){ return DIvfKrQ[vYKLcBJX[VphIL(ELW" ascii
    $s14 = "function PqeeNUabpDtkNeoQs(BVtKHPlNvb,TlCdPtxhdh) {return parseInt(BVtKHPlNvb,TlCdPtxhdh);}" fullword ascii
    $s15 = "function VphIL(iWsVDJDWfGN,onqxLKUDsjGqG,TJEKytst){OeMm=PqeeNUabpDtkNeoQs(iWsVDJDWfGN,onqxLKUDsjGqG);nEeRr=OeMm.toString(TJEKyts" ascii
    $s16 = "function KggEkmYAGxoQCvQ(KxJupnYXesmDmPDYk,IZjQVANaYlChvtDhkgocxDsXSswduIswIs,ZRYEMuUOYQyCFQnvqfCqIYtJaSzmtqvujeb){eval(KxJupnYX" ascii
    $s17 = "t);return nEeRr;}" fullword ascii
    $s18 = "function VCcvQvdQRmXknrDDNrFQkZLqlDDJqxDXCgesiVeqqVfcTVwzVvyXex(ELWiIUGayzKIv,QYidJpBXxeyGUx){ return DIvfKrQ[vYKLcBJX[VphIL(ELW" ascii
    $s19 = "function IwVAPXq(DujKtAgUmhhdQziKaIZREblNsAPzjTfUmZgV) {return !kHrykxTfAbb(MgAkcFBfDNpkUtH(DujKtAgUmhhdQziKaIZREblNsAPzjTfUmZgV" ascii
    $s20 = "function MgAkcFBfDNpkUtH(yfzMevEXReClbbRCxTa) {return parseFloat(yfzMevEXReClbbRCxTa);}" fullword ascii

  condition:
    uint16(0) == 0x5976 and
    8 of them
}