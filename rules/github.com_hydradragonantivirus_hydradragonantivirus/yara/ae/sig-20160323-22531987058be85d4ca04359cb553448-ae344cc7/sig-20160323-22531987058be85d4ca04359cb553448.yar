rule sig_20160323_22531987058be85d4ca04359cb553448 {
  meta:
    description = "datamaliciousorder - file 20160323_22531987058be85d4ca04359cb553448.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c10136fb8b2e847d46dd6a0561ac506df601dad7c8c112f8c860ec5fe51fc831"

  strings:
    $s1  = "return WScript.CreateObject(woYLf);" fullword ascii
    $s2  = "return ZnmWgKc[0] + ZnmWgKc[2] + ZnmWgKc[4] + \".F\" + ZnmWgKc[7] + ZnmWgKc[9] + ZnmWgKc[12] + ZnmWgKc[14];" fullword ascii
    $s3  = "var Dm = true  , nqMk = OuO[7] + OuO[9] + OuO[11];" fullword ascii
    $s4  = "var ZnmWgKc = zzFHv(OObMAlWQYc+\" \"+\"System Wf QrBdK Obj GPKKWJ ect FDgzrwz cqkBz\", \" \");" fullword ascii
    $s5  = "var OuO = (\"2.XMLHTTP mtQPbRE ihiAM XML ream St pypMpoDP AD fYzxNAQ O OvjC D\").split(\" \");" fullword ascii
    $s6  = "BSqH.open(wLjRD,vNJzq,false);" fullword ascii
    $s7  = "if(m>=h.length) {break;}" fullword ascii
    $s8  = "function boaM(dnzXe,LKAVw) {" fullword ascii
    $s9  = "return new ActiveXObject(duqX);" fullword ascii
    $s10 = "function qXTanLO(NGzi) {" fullword ascii
    $s11 = "function zvdTC(sOIMeG) {" fullword ascii
    $s12 = "function tZcTRRQW(hYTc) {" fullword ascii
    $s13 = "function ltLyBNIhv(afpfH) {" fullword ascii
    $s14 = "function ChkS(HWZUe) {" fullword ascii
    $s15 = "function Muxc(dXFEK) {" fullword ascii
    $s16 = "return YRjUjs/*1WMdbO6aDsBDGFpFv5MhbbcP9*/.position=910-910;" fullword ascii
    $s17 = "function GGAxYtGQZ(TEiqUCeiTwL) {" fullword ascii
    $s18 = "return NGzi[KJEaFd[0]];" fullword ascii
    $s19 = "function uYYh(KmpbM,vNJzq,wLjRD) {" fullword ascii
    $s20 = "if (P >= HWZUe.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}