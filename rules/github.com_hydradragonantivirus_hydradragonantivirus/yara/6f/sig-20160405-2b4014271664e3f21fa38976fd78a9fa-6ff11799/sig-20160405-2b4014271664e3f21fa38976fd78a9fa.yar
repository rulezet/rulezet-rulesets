rule sig_20160405_2b4014271664e3f21fa38976fd78a9fa {
  meta:
    description = "datamaliciousorder - file 20160405_2b4014271664e3f21fa38976fd78a9fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3115223995fa00717c07feacf86410d72910b0582102da6fa297c9d7e27988e3"

  strings:
    $s1  = "return kdxHTOU[0] + kdxHTOU[2] + kdxHTOU[4] + \".F\" + kdxHTOU[7] + kdxHTOU[9] + kdxHTOU[12] + kdxHTOU[14];" fullword ascii
    $s2  = "var lc = true  , CfJx = lfg[7] + lfg[9] + lfg[11];" fullword ascii
    $s3  = "yfwE.open(HBkcc,RHsNw,false);" fullword ascii
    $s4  = "var lfg = (\"2.XMLHTTP PWZbcxv ZMYpt XML ream St iENihnhX AD jUaWVJe O rFdH D\").split(\" \");" fullword ascii
    $s5  = "if(r>=s.length) {break;}" fullword ascii
    $s6  = "function QDxl(OYYgZ) {" fullword ascii
    $s7  = "if (rXuuo == 1095-895){return true;} else {return false;}" fullword ascii
    $s8  = "function tKLakyR(GYqU,Bpijm) {" fullword ascii
    $s9  = "function cJlXbDK(Hszf) {" fullword ascii
    $s10 = "function iOPs(ZAoEp,rgihv) {" fullword ascii
    $s11 = "return pupIi;" fullword ascii
    $s12 = "function IGyp(rXuuo) {" fullword ascii
    $s13 = "function mQSfQ(xCO,vwAHn) {" fullword ascii
    $s14 = "function PjNU(tHTOA) {" fullword ascii
    $s15 = "function EtiC(qyyaj,NoLuM) {" fullword ascii
    $s16 = "return XVLs;" fullword ascii
    $s17 = "function kwXvD(miYPxb) {" fullword ascii
    $s18 = "IPh = r; break; " fullword ascii
    $s19 = "function IGMHI(nAqxgmda,SVIS) {" fullword ascii
    $s20 = "return new ActiveXObject(JjaV);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}