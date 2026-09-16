rule sig_20160530_61277baa6e0cde8db001163b56000e75 {
  meta:
    description = "datamaliciousorder - file 20160530_61277baa6e0cde8db001163b56000e75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15421caf2489544f69467d394ed77180ef9c21cd5c59b8c0a74786bb3db2333a"

  strings:
    $s1  = "var IBZZPceBfzjYf=function(){return WScript.CreateObject(bFwFL[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function uoxZMT(WhgcupTxHbQLLExcbLBEq,AUvskReci){return WhgcupTxHbQLLExcbLBEq.charAt(AUvskReci);}" fullword ascii
    $s3  = "zyvqFTzJOno.length;fLApZTZqA++) {pBRGElK+=XKHLwUP[yyzyvqFTzJOno[fLApZTZqA]];}return pBRGElK.substring(3,pBRGElK.length);}" fullword ascii
    $s4  = "function LuuIoWxNSAnzW(){return IBZZPceBfzjYf.ExpandEnvironmentStrings(mogpQpK())}" fullword ascii
    $s5  = "function DsCMexCrxMDq(XkdRgAjpIzoTw) {var PhFnKyzMgIf = kzkpvcZzkojufocQQuN.join(bFwFL[7]);var KkmhzwawzJbHkxQHqVO, wOFoVHPhBcIP" ascii
    $s6  = "fkAKxGiwNGClyGxQox += cW(KkmhzwawzJbHkxQHqVO);else if (ZurRutRSm == 64) iGUyOkfkAKxGiwNGClyGxQox += IsuUTyqKOMBiPGnIPGm(Kkmhzwaw" ascii
    $s7  = "function nmSBE(pPYbQDpCsBP,yyzyvqFTzJOno,EoFma){XKHLwUP=pPYbQDpCsBP.split(EoFma);pBRGElK = bFwFL[0];for(fLApZTZqA=0;fLApZTZqA<yy" ascii
    $s8  = "function DsCMexCrxMDq(XkdRgAjpIzoTw) {var PhFnKyzMgIf = kzkpvcZzkojufocQQuN.join(bFwFL[7]);var KkmhzwawzJbHkxQHqVO, wOFoVHPhBcIP" ascii
    $s9  = "function UAURDvbK(){return nmSBE(bFwFL[13],[0,3,6],bFwFL[14]);}" fullword ascii
    $s10 = "function umdCQ(GBmsoepvg,jpGUYBjLR) {var yFEMI=[bFwFL[15]];GBmsoepvg[yFEMI[0]]" fullword ascii
    $s11 = "function mwSHxfOT(){return nmSBE(bFwFL[11],[2,4,8,10],bFwFL[12]);}" fullword ascii
    $s12 = "function jQigiYqyaykAGN(ooSuzTsGBCSTJwvunwMLmHG,gclLyvlwxlkikzVhYM){return ooSuzTsGBCSTJwvunwMLmHG.indexOf(gclLyvlwxlkikzVhYM);}" ascii
    $s13 = "zJbHkxQHqVO, wOFoVHPhBcIPo);else iGUyOkfkAKxGiwNGClyGxQox += crAFoWgmARwzYXPsxX(KkmhzwawzJbHkxQHqVO, wOFoVHPhBcIPo, UWHVVTfV);} " ascii
    $s14 = "function crAFoWgmARwzYXPsxX(dAPHt,MuZujGKMjAgptihVW,keskRfMmqIZ){return String.fromCharCode(dAPHt,MuZujGKMjAgptihVW,keskRfMmqIZ)" ascii
    $s15 = "var YrpowUGg=function(){return new ActiveXObject(bFwFL[1]);}();" fullword ascii
    $s16 = "function IsuUTyqKOMBiPGnIPGm(kNTom,IWOBScCZYpcqxZWxj){return String.fromCharCode(kNTom,IWOBScCZYpcqxZWxj);}" fullword ascii
    $s17 = "function cW(tSOBUK){return String.fromCharCode(tSOBUK);}" fullword ascii
    $s18 = "while (VezotYgoXrozpjjAuuWR < XkdRgAjpIzoTw.length);return iGUyOkfkAKxGiwNGClyGxQox;}" fullword ascii
    $s19 = "var IieiYG = YrpowUGg.createtextfile(IBZZPceBfzjYf.ExpandEnvironmentStrings(bFwFL[3]+bFwFL[4])+String.fromCharCode(92)+bFwFL[5]," ascii
    $s20 = "function mogpQpK(){return nmSBE(bFwFL[9],[1,5,7],bFwFL[10]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}