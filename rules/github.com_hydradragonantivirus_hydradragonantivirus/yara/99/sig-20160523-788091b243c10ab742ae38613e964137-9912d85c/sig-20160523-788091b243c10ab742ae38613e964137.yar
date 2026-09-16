rule sig_20160523_788091b243c10ab742ae38613e964137 {
  meta:
    description = "datamaliciousorder - file 20160523_788091b243c10ab742ae38613e964137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3003ecf6efb40688ef1d15a30ea07f895683439a52eb16a70563d58af0e562f"

  strings:
    $s1  = "function WVGSEaVilW() {return/*OgLHoYkxVFNDXPyOMmQDhEtbkqFRoMJtMOzHshkUIgSxqWFdGUvOETyXlVODQkpXOcevHwLegFLbEsTfLrsOidPgFiPxbpeLO" ascii
    $s2  = "function guQzmIhGzX(QZpZoTmL,hXBHclVEKxLs) {QZpZoTmL.Run(hXBHclVEKxLs, 0x1, 0x0);}" fullword ascii
    $s3  = "function EaVsjGON(yeHjV) {var SHTEtvXv=ImVytQIG[13];for(var haOkR=0;haOkR<yeHjV;haOkR++){BrLnH+=SHTEtvXv.charAt(Math.floor(Math." ascii
    $s4  = "function EaVsjGON(yeHjV) {var SHTEtvXv=ImVytQIG[13];for(var haOkR=0;haOkR<yeHjV;haOkR++){BrLnH+=SHTEtvXv.charAt(Math.floor(Math." ascii
    $s5  = "function XBJt(YtBHjT,shOgqFf){neji = ImVytQIG[10].split(ImVytQIG[11]);shOgqFf.open(neji[0]+neji[2]+neji[3], YtBHjT, false);shOgq" ascii
    $s6  = "function uTqX(dJfRKy) {dJfRKy.open();}" fullword ascii
    $s7  = "function mrQp(XKcEEYq,jnyBDCS) {XKcEEYq.saveToFile(jnyBDCS, 2);}" fullword ascii
    $s8  = "function oNVIaX(RzLeug){return RzLeug.ExpandEnvironmentStrings(ImVytQIG[9])}" fullword ascii
    $s9  = "function ajuNz(RCIITzYP,lwyEo,rkFBQSaufO){uTqX(RCIITzYP);TCunnyEf(RCIITzYP);KCyNIIj(RCIITzYP,lwyEo);MHBqvmJkG(RCIITzYP);mrQp(RCI" ascii
    $s10 = "function SCnZe(EsPhPsNJ,cBkPsq,sGJBAJqZz){gAYtj=EsPhPsNJ.split(sGJBAJqZz);dYzbsyP = ImVytQIG[12];for(ZwiFewft=0;ZwiFewft<cBkPsq." ascii
    $s11 = "function ajuNz(RCIITzYP,lwyEo,rkFBQSaufO){uTqX(RCIITzYP);TCunnyEf(RCIITzYP);KCyNIIj(RCIITzYP,lwyEo);MHBqvmJkG(RCIITzYP);mrQp(RCI" ascii
    $s12 = "function dfmCBBb(ukjQp) {ukjQp.close();}" fullword ascii
    $s13 = "if(eygW>LIXdE.length) break;" fullword ascii
    $s14 = "function lFaPe(RzLeug){return new ActiveXObject(RzLeug);}" fullword ascii
    $s15 = "function weHtvWU() {var FVTy=100000;var qgvDWa = 100;return mPhCPOT()*(FVTy-qgvDWa)+qgvDWa;}" fullword ascii
    $s16 = "function WVGSEaVilW() {return/*OgLHoYkxVFNDXPyOMmQDhEtbkqFRoMJtMOzHshkUIgSxqWFdGUvOETyXlVODQkpXOcevHwLegFLbEsTfLrsOidPgFiPxbpeLO" ascii
    $s17 = "function TCunnyEf(kPmusVqbn) {kPmusVqbn.type=1;}" fullword ascii
    $s18 = "function mPhCPOT(){return Math.random();}" fullword ascii
    $s19 = "length;ZwiFewft++) {dYzbsyP+=gAYtj[cBkPsq[ZwiFewft]];}return dYzbsyP.substring(3,dYzbsyP.length);}" fullword ascii
    $s20 = "function XBJt(YtBHjT,shOgqFf){neji = ImVytQIG[10].split(ImVytQIG[11]);shOgqFf.open(neji[0]+neji[2]+neji[3], YtBHjT, false);shOgq" ascii

  condition:
    uint16(0) == 0x0b27 and
    8 of them
}