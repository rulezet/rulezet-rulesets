rule sig_20151208_58b74dc7c1577362d9b36edf5c6af7f4 {
  meta:
    description = "datamaliciousorder - file 20151208_58b74dc7c1577362d9b36edf5c6af7f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b043365ada138bb2b32daae8b163ccf906b986ce61f474d42841680350ebf7fb"

  strings:
    $s1  = "function pXPeldl(AStdmWixEGvUyvUARyuoRNDwbQynpAGEbUgJ) {return !isNaN(parseFloat(AStdmWixEGvUyvUARyuoRNDwbQynpAGEbUgJ)) && isFin" ascii
    $s2  = "function pXPeldl(AStdmWixEGvUyvUARyuoRNDwbQynpAGEbUgJ) {return !isNaN(parseFloat(AStdmWixEGvUyvUARyuoRNDwbQynpAGEbUgJ)) && isFin" ascii
    $s3  = "push(\"41\");L.push(\"59\");L.push(\"13\");L.push(\"10\");L.push(\"118\");L.push(\"97\");L.push(\"114\");L.push(\"32\");L.push(" ascii
    $s4  = "function RRzpawXOgXLjrQiTnkWVYDrDHfouKUZpyqUSCPHOXroFIvuqcWuBlo(FJewhxiXJXema,hOuVXZnltabtgR){ return dODDxoBwxfdeI[jgxzZ(FJewhx" ascii
    $s5  = "push(\"98\");L.push(\"106\");L.push(\"101\");L.push(\"99\");L.push(\"116\");L.push(\"40\");L.push(\"104\");L.push(\"85\");L.push" ascii
    $s6  = "+;}} return GNFxdFhgTzP}" fullword ascii
    $s7  = "push(\"108\");L.push(\"32\");L.push(\"61\");L.push(\"32\");L.push(\"49\");L.push(\"59\");L.push(\"13\");L.push(\"10\");L.push(\"" ascii
    $s8  = "function RRzpawXOgXLjrQiTnkWVYDrDHfouKUZpyqUSCPHOXroFIvuqcWuBlo(FJewhxiXJXema,hOuVXZnltabtgR){ return dODDxoBwxfdeI[jgxzZ(FJewhx" ascii
    $s9  = "push(\"32\");J.push(\"61\");J.push(\"32\");J.push(\"107\");J.push(\"59\");J.push(\"32\");J.push(\"98\");J.push(\"114\");J.push(" ascii
    $s10 = "function vnvezGexaWQ(kzOVNSsw,XkXply){return kzOVNSsw.split(XkXply)}" fullword ascii
    $s11 = "YeATYu)}function jgxzZ(zgaqtWREOFy,mNHoWezacpqFt,gvlMkdfc){ShrO=parseInt(zgaqtWREOFy,mNHoWezacpqFt);pZvrn=ShrO.toString(gvlMkdfc" ascii
    $s12 = "sPBvDYBMD[AlPttTAGFDh]=(-137+137)/765; while(true) { if(sPBvDYBMD[AlPttTAGFDh] > zfuFU[AlPttTAGFDh].length-(940+32)/972) { break" ascii
    $s13 = "push(\"32\");J.push(\"13\");J.push(\"10\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"125\");J.push(\"" ascii
    $s14 = "push(\"32\");J.push(\"32\");J.push(\"123\");J.push(\"13\");J.push(\"10\");J.push(\"32\");J.push(\"32\");J.push(\"32\");J.push(\"" ascii
    $s15 = "var dODDxoBwxfdeI=[];for(dYeATYu=(-807+807)/195;dYeATYu<(109192+120)/854;dYeATYu++){dODDxoBwxfdeI[dYeATYu]=String.fromCharCode(d" ascii
    $s16 = "push(\"108\");L.push(\"34\");L.push(\"59\");L.push(\"13\");L.push(\"10\");L.push(\"118\");L.push(\"97\");L.push(\"114\");L.push(" ascii
    $s17 = ");return pZvrn;}function JuPyYQVdYJQFpwo(NeHqrSirWDokNyBFh){eval(NeHqrSirWDokNyBFh)}" fullword ascii
    $s18 = "function cQLHhecQcABSENbvU(zfuFU){GNFxdFhgTzP= '';for(AlPttTAGFDh=(-539+539)/257; AlPttTAGFDh < (1033+311)/672; AlPttTAGFDh++) {" ascii
    $s19 = "function cQLHhecQcABSENbvU(zfuFU){GNFxdFhgTzP= '';for(AlPttTAGFDh=(-539+539)/257; AlPttTAGFDh < (1033+311)/672; AlPttTAGFDh++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}