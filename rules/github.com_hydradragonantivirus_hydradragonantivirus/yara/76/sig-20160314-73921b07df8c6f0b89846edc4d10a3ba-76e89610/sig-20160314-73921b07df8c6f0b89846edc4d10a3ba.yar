rule sig_20160314_73921b07df8c6f0b89846edc4d10a3ba {
  meta:
    description = "datamaliciousorder - file 20160314_73921b07df8c6f0b89846edc4d10a3ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01dc600599693a5e673ea264aac1e2cd36045986c3d1ababf500254b91eedae6"

  strings:
    $s1  = "return ccNadVi[0] + ccNadVi[2] + ccNadVi[4] + \".F\" + ccNadVi[7] + ccNadVi[9] + ccNadVi[12] + ccNadVi[14];" fullword ascii
    $s2  = "var cL = true  , SiYw = eJS[7] + eJS[9] + eJS[11];" fullword ascii
    $s3  = "var eJS = (\"2.XMLHTTP WUXCjip ftozg XML ream St yViyJYAW AD xhVFEkl O ktcv D\").split(\" \");" fullword ascii
    $s4  = "var ccNadVi = \"Sc vPwsgZo r UHVbQDVeB ipting NGeSQCx kPj ile dsVIAZcbvFnYmE System Fv Sjlzv Obj vYATnO ect wHuNmAO sWKsE\".spli" ascii
    $s5  = "var ccNadVi = \"Sc vPwsgZo r UHVbQDVeB ipting NGeSQCx kPj ile dsVIAZcbvFnYmE System Fv Sjlzv Obj vYATnO ect wHuNmAO sWKsE\".spli" ascii
    $s6  = "OTLsa.open(SHuPc,MNNcn,false);" fullword ascii
    $s7  = "if (yRSEe == 405-205){return true;} else {return false;}" fullword ascii
    $s8  = "function BMra(ysgjF) {" fullword ascii
    $s9  = "return OYzxY.status;" fullword ascii
    $s10 = "function Lcfk(yEuri,YxCpL) {" fullword ascii
    $s11 = "function WTLB(sKbXP) {" fullword ascii
    $s12 = "return hZxGCDg(XN,EKSqx[518-512]+EKSqx[620-613]+EKSqx[489-481]);" fullword ascii
    $s13 = "function hZxGCDg(TZni,ncBRg) {" fullword ascii
    $s14 = "return new ActiveXObject(TqSpiw);" fullword ascii
    $s15 = "return TZni.ExpandEnvironmentStrings(ncBRg);" fullword ascii
    $s16 = "return oFhEPQy" fullword ascii
    $s17 = "function jcNuJVYfS(vPJOeHpyCes) {" fullword ascii
    $s18 = "function Azdg(OYzxY) {" fullword ascii
    $s19 = "function ioTE(yRSEe) {" fullword ascii
    $s20 = "return FsgJ.responseBody;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}