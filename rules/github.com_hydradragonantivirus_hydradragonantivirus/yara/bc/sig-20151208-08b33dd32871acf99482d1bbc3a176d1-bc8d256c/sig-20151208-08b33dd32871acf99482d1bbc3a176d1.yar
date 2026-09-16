rule sig_20151208_08b33dd32871acf99482d1bbc3a176d1 {
  meta:
    description = "datamaliciousorder - file 20151208_08b33dd32871acf99482d1bbc3a176d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee4b8b9d5f8fc6c04780a6b7e2b12dd9064fb76474157d47c0f45b12d6f9de56"

  strings:
    $s1  = "function TQvQBFs(nNCcmhscZGjWovLgIUujOTPTdmHEhPgQgUwh) {return !isNaN(parseFloat(nNCcmhscZGjWovLgIUujOTPTdmHEhPgQgUwh)) && isFin" ascii
    $s2  = "function TQvQBFs(nNCcmhscZGjWovLgIUujOTPTdmHEhPgQgUwh) {return !isNaN(parseFloat(nNCcmhscZGjWovLgIUujOTPTdmHEhPgQgUwh)) && isFin" ascii
    $s3  = "pXUME)}function qxmvl(JVuYPnkLjVK,WBRIAOmrIOzTU,TqRZGhsO){iokD=parseInt(JVuYPnkLjVK,WBRIAOmrIOzTU);junlA=iokD.toString(TqRZGhsO)" ascii
    $s4  = "push(\"41\");x.push(\"59\");x.push(\"13\");x.push(\"10\");x.push(\"118\");x.push(\"97\");x.push(\"114\");x.push(\"32\");x.push(" ascii
    $s5  = "function oXzpIgzbStfGxVgdJkmcRDgmwuLjGUQJlHQlqMMQmkJiGWyVTMflxn(ghUtAnvCzudGf,FLTgXalJxibFWb){ return DTbiFMkSDQDsW[qxmvl(ghUtAn" ascii
    $s6  = "function NrVtdRXuXxVBLPerl(kxjcP){GowOSgrOLIL= '';for(WCGEsYnaZNn=(-663+663)/813; WCGEsYnaZNn < (571+303)/437; WCGEsYnaZNn++) {C" ascii
    $s7  = "push(\"77\");z.push(\"73\");z.push(\"102\");z.push(\"47\");z.push(\"42\");z.push(\"84\");z.push(\"121\");z.push(\"85\");z.push(" ascii
    $s8  = "}} return GowOSgrOLIL}" fullword ascii
    $s9  = "VNvxZkcx[WCGEsYnaZNn]=(-951+951)/782; while(true) { if(CVNvxZkcx[WCGEsYnaZNn] > kxjcP[WCGEsYnaZNn].length-(-87+470)/383) { break" ascii
    $s10 = "push(\"32\");x.push(\"61\");x.push(\"32\");x.push(\"49\");x.push(\"51\");x.push(\"56\");x.push(\"55\");x.push(\"51\");x.push(\"5" ascii
    $s11 = "function JpXjZLPxuTs(PvvDJvKW,rNPCWk){return PvvDJvKW.split(rNPCWk)}" fullword ascii
    $s12 = "push(\"59\");z.push(\"9\");z.push(\"32\");z.push(\"13\");z.push(\"10\");z.push(\"32\");z.push(\"32\");z.push(\"32\");z.push(\"32" ascii
    $s13 = "function oXzpIgzbStfGxVgdJkmcRDgmwuLjGUQJlHQlqMMQmkJiGWyVTMflxn(ghUtAnvCzudGf,FLTgXalJxibFWb){ return DTbiFMkSDQDsW[qxmvl(ghUtAn" ascii
    $s14 = "function NrVtdRXuXxVBLPerl(kxjcP){GowOSgrOLIL= '';for(WCGEsYnaZNn=(-663+663)/813; WCGEsYnaZNn < (571+303)/437; WCGEsYnaZNn++) {C" ascii
    $s15 = "push(\"43\");x.push(\"40\");x.push(\"51\");x.push(\"48\");x.push(\"54\");x.push(\"55\");x.push(\"56\");x.push(\"53\");x.push(\"4" ascii
    $s16 = ";return junlA;}function OFaPeaYElPCSZWU(cavoXymTnkGAocRwE){eval(cavoXymTnkGAocRwE)}" fullword ascii
    $s17 = "var DTbiFMkSDQDsW=[];for(ALpXUME=(-812+812)/489;ALpXUME<(22579+589)/181;ALpXUME++){DTbiFMkSDQDsW[ALpXUME]=String.fromCharCode(AL" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}