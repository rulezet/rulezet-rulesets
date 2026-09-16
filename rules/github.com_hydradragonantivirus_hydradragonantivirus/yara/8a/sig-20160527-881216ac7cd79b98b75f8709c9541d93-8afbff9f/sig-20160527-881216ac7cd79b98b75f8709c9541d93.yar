rule sig_20160527_881216ac7cd79b98b75f8709c9541d93 {
  meta:
    description = "datamaliciousorder - file 20160527_881216ac7cd79b98b75f8709c9541d93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2809cfb5119088f11ddd7198dfd0233d51a0c5085db49914ac806717c2fcf336"

  strings:
    $s1  = "function ONoGjURhC() {return WScript;}function PaUBDmbtQzx(){return bUJyngZXvFvaiQ.ExpandEnvironmentStrings(BdtQjxg())}" fullword ascii
    $s2  = "function CrmKzjlOEDHeyqb(UIkmLxnNuwGUvW,UNRnulzjFFu){return UIkmLxnNuwGUvW.charAt(UNRnulzjFFu);}" fullword ascii
    $s3  = "function JDOmGXpOGtr(mUcXzEXBeofIU) {var OgMgjxrPtEux = HenyHzAwwWAsJbdAqpVBYusP.join(AbrbptNrtTOPOOvY[6]);var LugZskEvAcrQwiVg," ascii
    $s4  = "BeofIU.length);return KfbPtmVWdUoN;}" fullword ascii
    $s5  = "function nNXVDekj(){return YhUDL(AbrbptNrtTOPOOvY[10],[2,4,8,10],AbrbptNrtTOPOOvY[11]);}" fullword ascii
    $s6  = "push(\"v\");HenyHzAwwWAsJbdAqpVBYusP.push(\"w\");HenyHzAwwWAsJbdAqpVBYusP.push(\"x\");HenyHzAwwWAsJbdAqpVBYusP.push(\"y\");HenyH" ascii
    $s7  = "se KfbPtmVWdUoN += PbTXsFCTWrawhOPpvMCYQHC(LugZskEvAcrQwiVg, IRzwAYmTpMrq, cUfYaHRhMevwdc);} while (PLNtPwOAwIDHuxRcWv < mUcXzEX" ascii
    $s8  = "function afmOdxDSne(){return YhUDL(AbrbptNrtTOPOOvY[12],[0,3,6],AbrbptNrtTOPOOvY[13]);}" fullword ascii
    $s9  = "mVWdUoN += ps(LugZskEvAcrQwiVg);else if (kYRMHS == 64) KfbPtmVWdUoN += UJlJQkUNDafUUCONKytsPv(LugZskEvAcrQwiVg, IRzwAYmTpMrq);el" ascii
    $s10 = "function YhUDL(HETmxxjQOSVu,ZzDpGLodgZ,FPOGUggR){NSvXeh=HETmxxjQOSVu.split(FPOGUggR);VdyLWYKm = AbrbptNrtTOPOOvY[14];for(oQWJnYG" ascii
    $s11 = "function UJlJQkUNDafUUCONKytsPv(LfvHnLMEhDDHVxQhbYiSC,otVNIqkmrCcslNXwxQLG){return String.fromCharCode(LfvHnLMEhDDHVxQhbYiSC,otV" ascii
    $s12 = "function ps(PVvyXGlUdSqUVgMiomdBgUSA){return String.fromCharCode(PVvyXGlUdSqUVgMiomdBgUSA);}" fullword ascii
    $s13 = "ltG=0;oQWJnYGltG<ZzDpGLodgZ.length;oQWJnYGltG++) {VdyLWYKm+=NSvXeh[ZzDpGLodgZ[oQWJnYGltG]];}return VdyLWYKm.substring(3,VdyLWYKm" ascii
    $s14 = "var EhvyDkz=function(){return new ActiveXObject(AbrbptNrtTOPOOvY[0]);}();" fullword ascii
    $s15 = "function sMYdRqrSuQOO(OijLYlqhoQFHWW,gHHwwtAwZdmznY){return OijLYlqhoQFHWW.indexOf(gHHwwtAwZdmznY);}" fullword ascii
    $s16 = "function SjSyWqelgiw(YdKqm,VZjWBVrJxOTXFc) {var AHPPVfULxX=[AbrbptNrtTOPOOvY[15]];YdKqm[AHPPVfULxX[0]](VZjWBVrJxOTXFc,0x1,0x0)}" fullword ascii
    $s17 = "function JDOmGXpOGtr(mUcXzEXBeofIU) {var OgMgjxrPtEux = HenyHzAwwWAsJbdAqpVBYusP.join(AbrbptNrtTOPOOvY[6]);var LugZskEvAcrQwiVg," ascii
    $s18 = "var DKNNuxL = EhvyDkz.createtextfile(bUJyngZXvFvaiQ.ExpandEnvironmentStrings(AbrbptNrtTOPOOvY[2]+AbrbptNrtTOPOOvY[3])+String.fro" ascii
    $s19 = "function YhUDL(HETmxxjQOSVu,ZzDpGLodgZ,FPOGUggR){NSvXeh=HETmxxjQOSVu.split(FPOGUggR);VdyLWYKm = AbrbptNrtTOPOOvY[14];for(oQWJnYG" ascii
    $s20 = "mCharCode(92)+AbrbptNrtTOPOOvY[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}