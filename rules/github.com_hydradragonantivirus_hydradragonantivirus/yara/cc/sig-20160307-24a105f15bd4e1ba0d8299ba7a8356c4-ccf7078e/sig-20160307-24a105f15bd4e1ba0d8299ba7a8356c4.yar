rule sig_20160307_24a105f15bd4e1ba0d8299ba7a8356c4 {
  meta:
    description = "datamaliciousorder - file 20160307_24a105f15bd4e1ba0d8299ba7a8356c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a9ef22407b199ce13ce14712af9cdf05cd188f07ccf63216501791939623337"

  strings:
    $s1  = "var yP = true  , HYfX = YiG[7] + YiG[9] + YiG[11];" fullword ascii
    $s2  = "return aBlKogo[0] + aBlKogo[2] + aBlKogo[4] + \".F\" + aBlKogo[7] + aBlKogo[9] + aBlKogo[12] + aBlKogo[14];" fullword ascii
    $s3  = "var aBlKogo = \"Sc Gnpbwrj r XpdxtIjni ipting vdSbKSm dyL ile IWWTBObOVroqqk System Vd RdEHv Obj APinsi ect XmnMugm\".split(\" " ascii
    $s4  = "var YiG = (\"2.XMLHTTP xuCzOjJ mtkCT XML ream St KtbvGZOA AD lmVLoWL O lfWI D\").split(\" \");" fullword ascii
    $s5  = "fRpqI.open(UkmAa,fwCDZ,false);" fullword ascii
    $s6  = "if (GQNBq > 158215-762){return true;} else {return false;}" fullword ascii
    $s7  = "function cMQw(GQNBq) {" fullword ascii
    $s8  = "function gkQk(JQSEO,GCUuQ) {" fullword ascii
    $s9  = "function qHVXsbpe() {" fullword ascii
    $s10 = "function wsYO(uHJVF) {" fullword ascii
    $s11 = "function yekO(AVkpy) {" fullword ascii
    $s12 = "function peNfrgN(VLIN) {" fullword ascii
    $s13 = "function oIcV(KvWBs) {" fullword ascii
    $s14 = "function LHyezcYik(uODynhZABfI) {" fullword ascii
    $s15 = "if(w>=h.length) {break;}" fullword ascii
    $s16 = "function CGdk(wyTJX) {" fullword ascii
    $s17 = "bvn = w; break; " fullword ascii
    $s18 = "return MF.ExpandEnvironmentStrings(IHsTm[6]+IHsTm[7]+IHsTm[8]);" fullword ascii
    $s19 = "function gYaPh(kAzwAC) {" fullword ascii
    $s20 = "if (((new Date())>0,7600384888)) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}