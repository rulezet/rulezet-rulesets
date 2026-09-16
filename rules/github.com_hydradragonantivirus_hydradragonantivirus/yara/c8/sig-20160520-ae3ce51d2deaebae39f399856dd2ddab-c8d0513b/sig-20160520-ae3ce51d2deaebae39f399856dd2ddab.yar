rule sig_20160520_ae3ce51d2deaebae39f399856dd2ddab {
  meta:
    description = "datamaliciousorder - file 20160520_ae3ce51d2deaebae39f399856dd2ddab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "346d62ab0f419f0dc116a40ed2ff4c9289251090c3bf9c3ba77e2d22dee28a34"

  strings:
    $s1  = "function tCUNbTkT(EdQSM) {var ykNLVrln=kpQQxuMFXuoExIVvvsAl[2];for(var NJpCS=0;NJpCS<EdQSM;NJpCS++){lFrBv+=ykNLVrln.charAt(Math." ascii
    $s2  = "function tCUNbTkT(EdQSM) {var ykNLVrln=kpQQxuMFXuoExIVvvsAl[2];for(var NJpCS=0;NJpCS<EdQSM;NJpCS++){lFrBv+=ykNLVrln.charAt(Math." ascii
    $s3  = "function sKerU(unRqYMjs,MaylDa,pGPmNPnIw){DbkoZ=unRqYMjs.split(pGPmNPnIw);UcOMKvZ = kpQQxuMFXuoExIVvvsAl[13];for(xpLwPOvs=0;xpLw" ascii
    $s4  = "function sKerU(unRqYMjs,MaylDa,pGPmNPnIw){DbkoZ=unRqYMjs.split(pGPmNPnIw);UcOMKvZ = kpQQxuMFXuoExIVvvsAl[13];for(xpLwPOvs=0;xpLw" ascii
    $s5  = "POvs<MaylDa.length;xpLwPOvs++) {UcOMKvZ+=DbkoZ[MaylDa[xpLwPOvs]];}return UcOMKvZ.substring(3,UcOMKvZ.length);}" fullword ascii
    $s6  = "function GwdahS(NJPFwe){return NJPFwe.ExpandEnvironmentStrings(kpQQxuMFXuoExIVvvsAl[10])}" fullword ascii
    $s7  = "3], iPYvfH, false);hPZGKfh.send();}" fullword ascii
    $s8  = "function IjqlD(WCfIcxjn,ZfHmN,fkVPCfifbb){WCfIcxjn.open();WCfIcxjn.type = 1;WCfIcxjn.write(ZfHmN);WCfIcxjn.position = 0;WCfIcxjn" ascii
    $s9  = "floor(Math.random()*ykNLVrln.length));}return lFrBv;}" fullword ascii
    $s10 = "try{NKAhqmZgx(tGlTI[Uvdr], FLBWubQ() + kpQQxuMFXuoExIVvvsAl[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function FLBWubQ() {var JcrG=100000;var SjtmXU = 100;return Math.random()*(JcrG-SjtmXU)+SjtmXU;}" fullword ascii
    $s12 = "function NKAhqmZgx(gwFoFJFvt,eDVHyyu,ijOWgexh){" fullword ascii
    $s13 = "function IjqlD(WCfIcxjn,ZfHmN,fkVPCfifbb){WCfIcxjn.open();WCfIcxjn.type = 1;WCfIcxjn.write(ZfHmN);WCfIcxjn.position = 0;WCfIcxjn" ascii
    $s14 = "function pKrDh(NJPFwe){return new ActiveXObject(NJPFwe);}" fullword ascii
    $s15 = "function ofHm(iPYvfH,hPZGKfh){jOCv = kpQQxuMFXuoExIVvvsAl[11].split(kpQQxuMFXuoExIVvvsAl[12]);hPZGKfh.open(jOCv[0]+jOCv[2]+jOCv[" ascii
    $s16 = "function ofHm(iPYvfH,hPZGKfh){jOCv = kpQQxuMFXuoExIVvvsAl[11].split(kpQQxuMFXuoExIVvvsAl[12]);hPZGKfh.open(jOCv[0]+jOCv[2]+jOCv[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}