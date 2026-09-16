rule sig_20160309_0ae3d37ef8d59bd6b3d4221b0753db6f {
  meta:
    description = "datamaliciousorder - file 20160309_0ae3d37ef8d59bd6b3d4221b0753db6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e68abb619c0e31495a14c46729109c1b90b29b9dae468fe9cf1c29a35cf689d"

  strings:
    $s1  = "return OMhvAPz[0] + OMhvAPz[2] + OMhvAPz[4] + \".F\" + OMhvAPz[7] + OMhvAPz[9] + OMhvAPz[12] + OMhvAPz[14];" fullword ascii
    $s2  = "var jN = true  , Shae = Cdu[7] + Cdu[9] + Cdu[11];" fullword ascii
    $s3  = "var Cdu = (\"2.XMLHTTP jxZRazj ZzWnt XML ream St hAOBowll AD vMZXsTd O LJAm D\").split(\" \");" fullword ascii
    $s4  = "gxSWZ.open(SjclL,nJzKc,false);" fullword ascii
    $s5  = "function aTdgKrJz(pwbMU,OZIxiM) {" fullword ascii
    $s6  = "function DZEHtSzL(mEM) {" fullword ascii
    $s7  = "function bjgsiCqFF(RsSwlIvORLH) {" fullword ascii
    $s8  = "function UhiDp(WfsCVp) {" fullword ascii
    $s9  = "function AkjHchtjk(ITKyK,aQORL,tApOw,FHra) {" fullword ascii
    $s10 = "return new ActiveXObject(WfsCVp);" fullword ascii
    $s11 = "return ElRrvVj" fullword ascii
    $s12 = "function sPbL(VuvQo) {" fullword ascii
    $s13 = "function wdFH(gxSWZ,nJzKc,SjclL) {" fullword ascii
    $s14 = "return mEM.size;" fullword ascii
    $s15 = "function tDlb(LQQHV) {" fullword ascii
    $s16 = "function jOfK(dGXDP) {" fullword ascii
    $s17 = "return srQMj.status;" fullword ascii
    $s18 = "return VwvEdda(xo,gTeaw[637-631]+gTeaw[950-943]+gTeaw[369-361]);" fullword ascii
    $s19 = "return fUGKB;" fullword ascii
    $s20 = "if(v>=w.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}