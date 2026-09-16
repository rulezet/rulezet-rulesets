rule sig_20160312_bdd69b55e880e53bd6ca043ac418bebb {
  meta:
    description = "datamaliciousorder - file 20160312_bdd69b55e880e53bd6ca043ac418bebb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "239006496b1a3595d3ef41925dd5391ad9ed39804e3f83a086bc41a90c9f725b"

  strings:
    $s1  = "var lNqEanZ = \"Sc tNDkSLK r uMLiVyXJn ipting LTKrQyd wRK ile FFCkyNFrBHggzF System iF geTwp Obj wBqmBz ect RGxCEVL\".split(\" " ascii
    $s2  = "return lNqEanZ[0] + lNqEanZ[2] + lNqEanZ[4] + \".F\" + lNqEanZ[7] + lNqEanZ[9] + lNqEanZ[12] + lNqEanZ[14];" fullword ascii
    $s3  = "var jV = true  , CHBJ = agv[7] + agv[9] + agv[11];" fullword ascii
    $s4  = "var agv = (\"2.XMLHTTP vHPpHhw HjprH XML ream St smkBgBGw AD fgGSuih O yhmL D\").split(\" \");" fullword ascii
    $s5  = "ZUBVu.open(nlLGu,iBuyT,false);" fullword ascii
    $s6  = "UHd.CreateFolder(Bawd);" fullword ascii
    $s7  = "function odzS(zaSGZ,GQJlv) {" fullword ascii
    $s8  = "function jqJa(nQBTj) {" fullword ascii
    $s9  = "return Jmdzgxp(af,UWqwu[107-101]+UWqwu[433-426]+UWqwu[373-365]);" fullword ascii
    $s10 = "function VziR(Phbxh) {" fullword ascii
    $s11 = "function XpXIXQr(jTvD) {" fullword ascii
    $s12 = "return bXxltt.position=461-461;" fullword ascii
    $s13 = "function yvCO(hyiGp) {" fullword ascii
    $s14 = "function Ilxr(HYxKA,TrUlb) {" fullword ascii
    $s15 = "function aanB(IWcXX) {" fullword ascii
    $s16 = "return ZLHHsRS" fullword ascii
    $s17 = "return jTvD.responseBody;" fullword ascii
    $s18 = "return fHTe.ExpandEnvironmentStrings(VLRza);" fullword ascii
    $s19 = "xXX = e; break; " fullword ascii
    $s20 = "return CuY.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}