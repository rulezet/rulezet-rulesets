rule sig_20160309_aaff654f93153b83941dc7e28ec1419a {
  meta:
    description = "datamaliciousorder - file 20160309_aaff654f93153b83941dc7e28ec1419a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd0f05072605d3aa2fabc188a5602b75104efdbda944a71279ad9d45b486ec0b"

  strings:
    $s1  = "var Ok = true  , UCRq = PuR[7] + PuR[9] + PuR[11];" fullword ascii
    $s2  = "return YKYJWWk[0] + YKYJWWk[2] + YKYJWWk[4] + \".F\" + YKYJWWk[7] + YKYJWWk[9] + YKYJWWk[12] + YKYJWWk[14];" fullword ascii
    $s3  = "kiKQK.open(KQvWD,wiCeR,false);" fullword ascii
    $s4  = "var YKYJWWk = \"Sc gldNqxk r yNOQWSFGh ipting fohjDmc Euk ile jvqRgEeTDVeZpm System Ip fWgkp Obj pYYluD ect UysnQeV\".split(\" " ascii
    $s5  = "var PuR = (\"2.XMLHTTP OLEdDfY KbtbK XML ream St ydXmwMAI AD AkzoyNR O Unba D\").split(\" \");" fullword ascii
    $s6  = "return LtLUdaE(sn,YZhxs[408-402]+YZhxs[672-665]+YZhxs[902-894]);" fullword ascii
    $s7  = "return NoIqs.status;" fullword ascii
    $s8  = "function Jydo(MGSTp,pNHNN) {" fullword ascii
    $s9  = "return JZSXR;" fullword ascii
    $s10 = "function DEfW(orMRV) {" fullword ascii
    $s11 = "return kxxP.responseBody;" fullword ascii
    $s12 = "function iSxJtIvr(BjzKA,vbQskp) {" fullword ascii
    $s13 = "function LtLUdaE(ZOyB,AlCBj) {" fullword ascii
    $s14 = "function EUTt(HPpXU) {" fullword ascii
    $s15 = "uzZ = N; break; " fullword ascii
    $s16 = "if(N>=g.length) {break;}" fullword ascii
    $s17 = "return OaGIUXI" fullword ascii
    $s18 = "return new ActiveXObject(ZuJHRQ);" fullword ascii
    $s19 = "function BgBMgpYr(TCx) {" fullword ascii
    $s20 = "function VTNz(Gkmmc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}