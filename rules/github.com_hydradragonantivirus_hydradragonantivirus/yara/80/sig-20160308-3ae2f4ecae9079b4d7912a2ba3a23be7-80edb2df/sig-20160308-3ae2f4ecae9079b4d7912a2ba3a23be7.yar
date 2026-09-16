rule sig_20160308_3ae2f4ecae9079b4d7912a2ba3a23be7 {
  meta:
    description = "datamaliciousorder - file 20160308_3ae2f4ecae9079b4d7912a2ba3a23be7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cd53a7169cf4d8fbe2c7771d9778e8eee06def4c6b9c9982665b2c231652d8f"

  strings:
    $s1  = "var aq = true  , baoE = ypK[7] + ypK[9] + ypK[11];" fullword ascii
    $s2  = "return ccEmavf[0] + ccEmavf[2] + ccEmavf[4] + \".F\" + ccEmavf[7] + ccEmavf[9] + ccEmavf[12] + ccEmavf[14];" fullword ascii
    $s3  = "var ccEmavf = \"Sc CkdyvhI r CblqJWYJO ipting jqfNEFQ FOV ile jjJrIfdVzfSAdL System Nk PkbUx Obj qWALTv ect unOhoHn\".split(\" " ascii
    $s4  = "var ypK = (\"2.XMLHTTP kCFKsUh kbRdt XML ream St WbwMgRWY AD xGuwixQ O vWHz D\").split(\" \");" fullword ascii
    $s5  = "AyMbN.open(iEJqf,nSYTL,false);" fullword ascii
    $s6  = "function clOLEAXtt(uhBQm,SxsqY,cjOri,ZxeS) {" fullword ascii
    $s7  = "function tYYg(fxspK) {" fullword ascii
    $s8  = "return Rn.ExpandEnvironmentStrings(kKRCI[6]+kKRCI[7]+kKRCI[8]);" fullword ascii
    $s9  = "return new ActiveXObject(nJZWiB);" fullword ascii
    $s10 = "return SRXo.responseBody;" fullword ascii
    $s11 = "function gXIy(AHXID,Gkrqb) {" fullword ascii
    $s12 = "return uuV.size;" fullword ascii
    $s13 = "return ZkgSj;" fullword ascii
    $s14 = "function xSeW(EdNoC) {" fullword ascii
    $s15 = "function xrRT(qDcxF) {" fullword ascii
    $s16 = "return MNrJgXw" fullword ascii
    $s17 = "function pBleGrLi() {" fullword ascii
    $s18 = "function OcLHs(nJZWiB) {" fullword ascii
    $s19 = "if (((new Date())>0,719912888)) {" fullword ascii
    $s20 = "function eKniXhbc(uuV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}