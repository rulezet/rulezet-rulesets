rule sig_20160527_ecb743ee0d79fcd432266c278cbb1bde {
  meta:
    description = "datamaliciousorder - file 20160527_ecb743ee0d79fcd432266c278cbb1bde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "636ea6a394671d5b1ed6fa36d8b673881d150649c38302ec6c8be4b710226c81"

  strings:
    $s1  = "function iJQLLwTCWUZGzvA(fKUROMotKLpFkxzUziavl,tBOZs){return fKUROMotKLpFkxzUziavl.charAt(tBOZs);}" fullword ascii
    $s2  = "function MRNrlHjYl() {return WScript;}function nMbnNjAqRbzjP(){return ZxOoCYyZfeA.ExpandEnvironmentStrings(cAfko())}" fullword ascii
    $s3  = "function rx(PFPCcIjTtsDClVCHu){return String.fromCharCode(PFPCcIjTtsDClVCHu);}" fullword ascii
    $s4  = "function UUuyikyRKhxpFbR(nUWcjrDAkqQkUposlizf,TKChUNQtZNtiisFhbByjz,zbweuYaOjfvozQBxzH){return String.fromCharCode(nUWcjrDAkqQkU" ascii
    $s5  = "var ZxOoCYyZfeA=function(){return MRNrlHjYl().CreateObject(qZTyb[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s6  = "function cjUxqTJxeEEgvQFOOX(OidSdPQNgZjprBpAhGLNN,moRPRTu){return OidSdPQNgZjprBpAhGLNN.indexOf(moRPRTu);}" fullword ascii
    $s7  = "var THejZXnx=function(){return new ActiveXObject(qZTyb[0]);}();" fullword ascii
    $s8  = "var YzVkTOKfI = THejZXnx.createtextfile(ZxOoCYyZfeA.ExpandEnvironmentStrings(qZTyb[2]+qZTyb[3])+String.fromCharCode(92)+qZTyb[4]" ascii
    $s9  = "function rfXJCeNLNk(IrSFmMBUiRoKo) {var VzXaJX = fnpDRVGYpKrYDcLYlCQI.join(qZTyb[6]);var zWwMJndlBMnTfEicmTxzXf, SjqRkmKlXbjQMlR" ascii
    $s10 = "64) nLfGsaoGaOnlhRT += rx(zWwMJndlBMnTfEicmTxzXf);else if (xxInLIGXezYs == 64) nLfGsaoGaOnlhRT += cCDmbpvilyfLOTWtmt(zWwMJndlBMn" ascii
    $s11 = "function rfXJCeNLNk(IrSFmMBUiRoKo) {var VzXaJX = fnpDRVGYpKrYDcLYlCQI.join(qZTyb[6]);var zWwMJndlBMnTfEicmTxzXf, SjqRkmKlXbjQMlR" ascii
    $s12 = "function cCDmbpvilyfLOTWtmt(jGVxLoJZg,vkNGQK){return String.fromCharCode(jGVxLoJZg,vkNGQK);}" fullword ascii
    $s13 = "function UUuyikyRKhxpFbR(nUWcjrDAkqQkUposlizf,TKChUNQtZNtiisFhbByjz,zbweuYaOjfvozQBxzH){return String.fromCharCode(nUWcjrDAkqQkU" ascii
    $s14 = "r(cRjSLCnHv=0;cRjSLCnHv<LmTxTnlQPUj.length;cRjSLCnHv++) {eEeWAtbW+=lIPiuk[LmTxTnlQPUj[cRjSLCnHv]];}return eEeWAtbW.substring(3,e" ascii
    $s15 = "OYVNu);} while (vAZcHKiQvAd < IrSFmMBUiRoKo.length);return nLfGsaoGaOnlhRT;}" fullword ascii
    $s16 = "function dnRjEtscSstx(iRLwtBwUypmDX,LmTxTnlQPUj,ovLzigOsNWpXz){lIPiuk=iRLwtBwUypmDX.split(ovLzigOsNWpXz);eEeWAtbW = qZTyb[14];fo" ascii
    $s17 = "TfEicmTxzXf, SjqRkmKlXbjQMlRFATordT);else nLfGsaoGaOnlhRT += UUuyikyRKhxpFbR(zWwMJndlBMnTfEicmTxzXf, SjqRkmKlXbjQMlRFATordT, rLV" ascii
    $s18 = "function LAnXIJQIbW(){return dnRjEtscSstx(qZTyb[12],[0,3,6],qZTyb[13]);}" fullword ascii
    $s19 = "function dnRjEtscSstx(iRLwtBwUypmDX,LmTxTnlQPUj,ovLzigOsNWpXz){lIPiuk=iRLwtBwUypmDX.split(ovLzigOsNWpXz);eEeWAtbW = qZTyb[14];fo" ascii
    $s20 = "function VTRfEAgF(xWzZegNk,KBEBGcjGa) {var AdEERjjSUxuaU=[qZTyb[15]];xWzZegNk[AdEERjjSUxuaU[0]](KBEBGcjGa,0x1,0x0)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}