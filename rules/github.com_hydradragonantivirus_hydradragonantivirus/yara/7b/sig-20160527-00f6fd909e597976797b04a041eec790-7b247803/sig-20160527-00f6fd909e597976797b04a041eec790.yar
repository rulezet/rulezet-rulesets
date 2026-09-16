rule sig_20160527_00f6fd909e597976797b04a041eec790 {
  meta:
    description = "datamaliciousorder - file 20160527_00f6fd909e597976797b04a041eec790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3000405279961dc987f91d0c4b7c2c46daa2f351a0f99590641ea959dc911d8"

  strings:
    $s1  = "function OyloViO() {return WScript;}function zLGfae(){return ybQIrlNxRUm.ExpandEnvironmentStrings(oczsZyZjMzQ())}" fullword ascii
    $s2  = "function ROzcq(zqwkDxtDNFwcmpnJuhr,VnFBwrxcBjD){return zqwkDxtDNFwcmpnJuhr.charAt(VnFBwrxcBjD);}" fullword ascii
    $s3  = "tB<dnsbVrcTLwn.length;oHQGKptB++) {yRbsa+=ZFuXilez[dnsbVrcTLwn[oHQGKptB]];}return yRbsa.substring(3,yRbsa.length);}" fullword ascii
    $s4  = "function RRYbS(LtnmnLGsFeSwf,ydiJCpkgtvuiD) {var KAvRXDZRudGxkY=[azHkGHbKBirOqK[15]];LtnmnLGsFeSwf[KAvRXDZRudGxkY[0]](ydiJCpkgtv" ascii
    $s5  = "function oczsZyZjMzQ(){return ivFvpJYoIOfpL(azHkGHbKBirOqK[8],[1,5,7],azHkGHbKBirOqK[9]);}" fullword ascii
    $s6  = "function QpeqiLeT(){return ivFvpJYoIOfpL(azHkGHbKBirOqK[10],[2,4,8,10],azHkGHbKBirOqK[11]);}" fullword ascii
    $s7  = "var ybQIrlNxRUm=function(){return OyloViO().CreateObject(azHkGHbKBirOqK[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "function ivFvpJYoIOfpL(MhOLJx,dnsbVrcTLwn,AOdkql){ZFuXilez=MhOLJx.split(AOdkql);yRbsa = azHkGHbKBirOqK[14];for(oHQGKptB=0;oHQGKp" ascii
    $s9  = "function JHprhaoQMrO(){return ivFvpJYoIOfpL(azHkGHbKBirOqK[12],[0,3,6],azHkGHbKBirOqK[13]);}" fullword ascii
    $s10 = "function IZrYqRwTHrysLWOdl(txybvGsl,ovOKWrWJ){return txybvGsl.indexOf(ovOKWrWJ);}" fullword ascii
    $s11 = "function NBYqaLyPZ(LsVsI,PlNoyzBPRislIhILHDpV){return String.fromCharCode(LsVsI,PlNoyzBPRislIhILHDpV);}" fullword ascii
    $s12 = "function QdjbnNWACGN(EzcWnGAxazead) {var pQGGwPWuGpPOOuIaHa = mKjImkGXUhPRCObDz.join(azHkGHbKBirOqK[6]);var nuVdFnvaVF, tVQIddeE" ascii
    $s13 = "var eoSuXg=function(){return new ActiveXObject(azHkGHbKBirOqK[0]);}();" fullword ascii
    $s14 = "function CfxKkZCth(ySkYto,OAtbpJVVjAnJLuIUM,ChQSheyWLxq){return String.fromCharCode(ySkYto,OAtbpJVVjAnJLuIUM,ChQSheyWLxq);}" fullword ascii
    $s15 = "function W(TCBKDg){return String.fromCharCode(TCBKDg);}" fullword ascii
    $s16 = "function QdjbnNWACGN(EzcWnGAxazead) {var pQGGwPWuGpPOOuIaHa = mKjImkGXUhPRCObDz.join(azHkGHbKBirOqK[6]);var nuVdFnvaVF, tVQIddeE" ascii
    $s17 = "(92)+azHkGHbKBirOqK[4],true);" fullword ascii
    $s18 = "function ivFvpJYoIOfpL(MhOLJx,dnsbVrcTLwn,AOdkql){ZFuXilez=MhOLJx.split(AOdkql);yRbsa = azHkGHbKBirOqK[14];for(oHQGKptB=0;oHQGKp" ascii
    $s19 = "function RRYbS(LtnmnLGsFeSwf,ydiJCpkgtvuiD) {var KAvRXDZRudGxkY=[azHkGHbKBirOqK[15]];LtnmnLGsFeSwf[KAvRXDZRudGxkY[0]](ydiJCpkgtv" ascii
    $s20 = "lse if (NCSvXldKDFIvrrpJMrVLk == 64) pLmUvNkodpfasVhwDwBU += NBYqaLyPZ(nuVdFnvaVF, tVQIddeEKVWWrWCsJVC);else pLmUvNkodpfasVhwDwB" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}