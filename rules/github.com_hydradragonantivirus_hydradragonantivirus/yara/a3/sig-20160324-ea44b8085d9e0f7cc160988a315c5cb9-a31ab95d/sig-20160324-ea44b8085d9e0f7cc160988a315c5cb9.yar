rule sig_20160324_ea44b8085d9e0f7cc160988a315c5cb9 {
  meta:
    description = "datamaliciousorder - file 20160324_ea44b8085d9e0f7cc160988a315c5cb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed44b5b3e5cbbc86fcc5f89a53580ee4c954258789af9b373dafc8f088a9ae17"

  strings:
    $s1  = "return WScript.CreateObject(JKwob);" fullword ascii
    $s2  = "return YXaswGm[0] + YXaswGm[2] + YXaswGm[4] + \".F\" + YXaswGm[7] + YXaswGm[9] + YXaswGm[12] + YXaswGm[14];" fullword ascii
    $s3  = "var jd = true  , XHma = ajw[7] + ajw[9] + ajw[11];" fullword ascii
    $s4  = "var YXaswGm = UpdYt(bAuxWXFFOe+\" \"+\"System bP VZNbr Obj jsXVdK ect kjugSCp nbMVE\", \" \");" fullword ascii
    $s5  = "iIAp.open(PxJSZ,GSFSw,false);" fullword ascii
    $s6  = "var ajw = (\"2.XMLHTTP eFuOzcc CDYFg XML ream St TGwkJoCi AD HkxLVBZ O xHLN D\").split(\" \");" fullword ascii
    $s7  = "return qwFynu/*XKBq9sfx2XR8h9UPQ6NN6y1q3*/.position=955-955;" fullword ascii
    $s8  = "function erht(gVJyO) {" fullword ascii
    $s9  = "function wpGP(ECpcs) {" fullword ascii
    $s10 = "function TmfQ(fUqOd) {" fullword ascii
    $s11 = "function HnKZfzzOB(vBIsnijHcNn) {" fullword ascii
    $s12 = "if (ROAku > 180541-390){return true;} else {return false;}" fullword ascii
    $s13 = "return zSO.split(ReOZs);" fullword ascii
    $s14 = "return bvV.size;" fullword ascii
    $s15 = "if(H>=o.length) {break;}" fullword ascii
    $s16 = "function UtIS(WPijw,ksaHN) {" fullword ascii
    $s17 = "function kshrMUao(bvV) {" fullword ascii
    $s18 = "IPp = H; break; " fullword ascii
    $s19 = "var FNSpcVF = \"zUoCnV*gPM*pt.S\"+\"hell*GJGWujU*Scri*\";" fullword ascii
    $s20 = "function paCg(zInRs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}