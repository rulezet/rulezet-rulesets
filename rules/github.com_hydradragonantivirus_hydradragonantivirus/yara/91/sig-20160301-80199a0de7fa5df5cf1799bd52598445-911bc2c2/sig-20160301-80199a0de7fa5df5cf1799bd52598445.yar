rule sig_20160301_80199a0de7fa5df5cf1799bd52598445 {
  meta:
    description = "datamaliciousorder - file 20160301_80199a0de7fa5df5cf1799bd52598445.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "662bdbf7c51fefc0f06bb92afc8dbe944f505dd5c5c6fcc33e8b257b159fe6f5"

  strings:
    $s1  = "var rO = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(anamy);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + FUdEQLd + \".F\" + HUpmSpIyJE + EWWNv + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var Rwp = (kYW + \"TTP\" + \" OXfVEmX Xzgvy XML ream St tAJKJxVI AD oNgGdhk OD\").split(\" \");" fullword ascii
    $s5  = "var Zx = true  , guQV = Rwp[7] + \"\" + Rwp[9];" fullword ascii
    $s6  = "mxtQI.open(BQmRW,GTrWS,false);" fullword ascii
    $s7  = "return cObpZ.status;" fullword ascii
    $s8  = "function yCwl(FxMBn,XUvrk) {" fullword ascii
    $s9  = "function pOaM(iXvmm) {" fullword ascii
    $s10 = "function xLcN(erBcR) {" fullword ascii
    $s11 = "function ZNZf(mjzDU) {" fullword ascii
    $s12 = "function CEakHxwFi(mqlyX,YAtXu,ecDQW) {" fullword ascii
    $s13 = "function HDECXAnRV(YqWoMRNhwFw) {" fullword ascii
    $s14 = "if (mhDHH == 893-693){return true;} else {return false;}" fullword ascii
    $s15 = "function TxKp(cObpZ) {" fullword ascii
    $s16 = "return ayIbI;" fullword ascii
    $s17 = "function prZX(anamy) {" fullword ascii
    $s18 = "function pVdO(mhDHH) {" fullword ascii
    $s19 = "return PV.ExpandEnvironmentStrings(rO);" fullword ascii
    $s20 = "function YFbU(SYjQI,PczEG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}