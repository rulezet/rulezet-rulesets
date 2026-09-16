rule sig_20151216_fd2c2e476d89554ff1c37d85fbc6b298 {
  meta:
    description = "datamaliciousorder - file 20151216_fd2c2e476d89554ff1c37d85fbc6b298.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e8427e92986903bc4670d68cda868b1a1a829982bb343df1b2cff96bd2069ff"

  strings:
    $s1  = ") - 1));while(true){if (ZZESrMxOzEB >= (1447+83)/255){break;}gLWFOIFRZ[ZZESrMxOzEB]=Math.round((Math.pow(Math.sin(254), 2) + Mat" ascii
    $s2  = "ow(Math.cos(778), 2) - 1)));} gLWFOIFRZ[ZZESrMxOzEB]++;}ZZESrMxOzEB++;} return KiGVmaPajDn}" fullword ascii
    $s3  = "function UWhStUseSGFFtQktP(nFvRt){KiGVmaPajDn= '';ZZESrMxOzEB=Math.round((Math.pow(Math.sin(874), 2) + Math.pow(Math.cos(874), 2" ascii
    $s4  = "h.pow(Math.cos(254), 2) - 1)); while(true) { if(gLWFOIFRZ[ZZESrMxOzEB] > nFvRt[ZZESrMxOzEB].length-(-90+701)/611) { break; } if " ascii
    $s5  = "function UWhStUseSGFFtQktP(nFvRt){KiGVmaPajDn= '';ZZESrMxOzEB=Math.round((Math.pow(Math.sin(874), 2) + Math.pow(Math.cos(874), 2" ascii
    $s6  = "function HdUWeyx(tjEkNTMxpMLBJGAIwkqazHJUWSVpCUrcPVhU) {return !VJRZjenlqQw(aySUKGSZKcMFMmo(tjEkNTMxpMLBJGAIwkqazHJUWSVpCUrcPVhU" ascii
    $s7  = "function LPQdvHoqwZnLXxbJGBLtHBnkDoomRxROgOjXZHKKojzVoIrqzwGDmw(ihVkvKNmtevaA,unNqQWCzTYITIr){ return dRjhqYX[YMkaGuuC[xGBlc(ihV" ascii
    $s8  = "function zJxxXCDuzSwg(OXOaCOfIlvCQv) {return isFinite(OXOaCOfIlvCQv);}" fullword ascii
    $s9  = "function xGBlc(BClGGcsaekA,jVQjGhwdOzhWG,YZvyjyeI){vTbZ=qsUOnCmEHsvGNCqly(BClGGcsaekA,jVQjGhwdOzhWG);kwejl=vTbZ.toString(YZvyjye" ascii
    $s10 = "function aySUKGSZKcMFMmo(EZRnRIFtBDiisogHgiF) {return parseFloat(EZRnRIFtBDiisogHgiF);}" fullword ascii
    $s11 = "function RhCqTRhGIoeeaLO(HeLzbsYlVYhnlTiUE,SsVshdUEidddABPryWbQrgeGeUGlfBxZSM,JYSNvkzZuwompnuTnWeoLxrFPpjCryCiodd){eval(HeLzbsYl" ascii
    $s12 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s13 = "function HdUWeyx(tjEkNTMxpMLBJGAIwkqazHJUWSVpCUrcPVhU) {return !VJRZjenlqQw(aySUKGSZKcMFMmo(tjEkNTMxpMLBJGAIwkqazHJUWSVpCUrcPVhU" ascii
    $s14 = "I);return kwejl;}" fullword ascii
    $s15 = "function I(SdPdKoIsdQGY,HOIjyarvqpulHz){SdPdKoIsdQGY.push(HOIjyarvqpulHz);}" fullword ascii
    $s16 = "function xGBlc(BClGGcsaekA,jVQjGhwdOzhWG,YZvyjyeI){vTbZ=qsUOnCmEHsvGNCqly(BClGGcsaekA,jVQjGhwdOzhWG);kwejl=vTbZ.toString(YZvyjye" ascii
    $s17 = "function qsUOnCmEHsvGNCqly(PKsFTLbyJc,FaSjoWkreB) {return parseInt(PKsFTLbyJc,FaSjoWkreB);}" fullword ascii
    $s18 = "function T(DVjdOkFLtaaqBv,kIJEMTeHSwPkb,iaCbEFRymtV) {DVjdOkFLtaaqBv[kIJEMTeHSwPkb]=iaCbEFRymtV;}" fullword ascii
    $s19 = "function LPQdvHoqwZnLXxbJGBLtHBnkDoomRxROgOjXZHKKojzVoIrqzwGDmw(ihVkvKNmtevaA,unNqQWCzTYITIr){ return dRjhqYX[YMkaGuuC[xGBlc(ihV" ascii
    $s20 = "function RhCqTRhGIoeeaLO(HeLzbsYlVYhnlTiUE,SsVshdUEidddABPryWbQrgeGeUGlfBxZSM,JYSNvkzZuwompnuTnWeoLxrFPpjCryCiodd){eval(HeLzbsYl" ascii

  condition:
    uint16(0) == 0x4d59 and
    8 of them
}