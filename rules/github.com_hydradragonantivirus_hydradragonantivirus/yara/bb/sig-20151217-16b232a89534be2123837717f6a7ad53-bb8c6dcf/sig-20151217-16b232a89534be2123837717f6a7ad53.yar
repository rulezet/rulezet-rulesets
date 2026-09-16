rule sig_20151217_16b232a89534be2123837717f6a7ad53 {
  meta:
    description = "datamaliciousorder - file 20151217_16b232a89534be2123837717f6a7ad53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16e93b48b69a4125c29ae6e8ecbedf8c8b199297287516403eaaf76ed2b485e5"

  strings:
    $s1  = "function fhkelrTaejKwkXNrV(cvyqP){DyxctUraWGj= '';ruXPuFcKJSc=Math.round((Math.pow(Math.sin(828), 2) + Math.pow(Math.cos(828), 2" ascii
    $s2  = "ow(Math.cos(297), 2) - 1)));} fIworhUBo[ruXPuFcKJSc]++;}ruXPuFcKJSc++;} return DyxctUraWGj}" fullword ascii
    $s3  = "h.pow(Math.cos(526), 2) - 1)); while(true) { if(fIworhUBo[ruXPuFcKJSc] > cvyqP[ruXPuFcKJSc].length-(676+241)/917) { break; } if " ascii
    $s4  = ") - 1));while(true){if (ruXPuFcKJSc >= (5585+85)/945){break;}fIworhUBo[ruXPuFcKJSc]=Math.round((Math.pow(Math.sin(526), 2) + Mat" ascii
    $s5  = "function fhkelrTaejKwkXNrV(cvyqP){DyxctUraWGj= '';ruXPuFcKJSc=Math.round((Math.pow(Math.sin(828), 2) + Math.pow(Math.cos(828), 2" ascii
    $s6  = "function AxCWysR(azbBLBFauxIUOGtkAgXtGfaisPWOrtMpaHlD) {return !onUcWmfvcwM(mnICxVGwCxZbipY(azbBLBFauxIUOGtkAgXtGfaisPWOrtMpaHlD" ascii
    $s7  = "function AxCWysR(azbBLBFauxIUOGtkAgXtGfaisPWOrtMpaHlD) {return !onUcWmfvcwM(mnICxVGwCxZbipY(azbBLBFauxIUOGtkAgXtGfaisPWOrtMpaHlD" ascii
    $s8  = "function BAplqGpowFIr(wPkICqbmwzTHK) {return isFinite(wPkICqbmwzTHK);}" fullword ascii
    $s9  = "function yPobr(ALvRwlkikmY,BKjeKHakOCJjq,xXFqPmKW){AOie=RmIxmzyKBAegSbiks(ALvRwlkikmY,BKjeKHakOCJjq);FHHnm=AOie.toString(xXFqPmK" ascii
    $s10 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s11 = "function yPobr(ALvRwlkikmY,BKjeKHakOCJjq,xXFqPmKW){AOie=RmIxmzyKBAegSbiks(ALvRwlkikmY,BKjeKHakOCJjq);FHHnm=AOie.toString(xXFqPmK" ascii
    $s12 = "function p(dMiwRMZfIMZA,dHnevKBkyOXcqr){dMiwRMZfIMZA.push(dHnevKBkyOXcqr);}" fullword ascii
    $s13 = "W);return FHHnm;}" fullword ascii
    $s14 = "function RmIxmzyKBAegSbiks(zUGhetxbts,RgwAqnmUUB) {return parseInt(zUGhetxbts,RgwAqnmUUB);}" fullword ascii
    $s15 = "function q(sffSviWaZBiYwi,NbBlXxCgtAFHU,WptkHEVfLrG) {sffSviWaZBiYwi[NbBlXxCgtAFHU]=WptkHEVfLrG;}" fullword ascii
    $s16 = "function mnICxVGwCxZbipY(iBUldhkPwnAOktPsVya) {return parseFloat(iBUldhkPwnAOktPsVya);}" fullword ascii
    $s17 = "function RHJksXioMbYhBcoILIeHIoiTEoDVgVhpBeebpovhLlToIpQwmNhqsd(PAqnTQbNpTMcf,ThkJUJaiieNGoG){ return ussxLQk[TmicSEoP[yPobr(PAq" ascii
    $s18 = "function onUcWmfvcwM(TDhHZBZQORzHYc) {return isNaN(TDhHZBZQORzHYc);}" fullword ascii
    $s19 = "function RHJksXioMbYhBcoILIeHIoiTEoDVgVhpBeebpovhLlToIpQwmNhqsd(PAqnTQbNpTMcf,ThkJUJaiieNGoG){ return ussxLQk[TmicSEoP[yPobr(PAq" ascii
    $s20 = "function hUljrYnKgyLAxCA(fegBooHFEiDWfBEIW,XtowFGzxLvKUXAPLXeaCExOQaihqnZFYSt,zDGWKOzVMGYFbYHccHPbMiFSPWVFfgHnTse){eval(fegBooHF" ascii

  condition:
    uint16(0) == 0x6d54 and
    8 of them
}