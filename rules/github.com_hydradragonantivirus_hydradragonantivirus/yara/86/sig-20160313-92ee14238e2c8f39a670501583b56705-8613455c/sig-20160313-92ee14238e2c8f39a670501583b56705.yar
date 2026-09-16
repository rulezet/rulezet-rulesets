rule sig_20160313_92ee14238e2c8f39a670501583b56705 {
  meta:
    description = "datamaliciousorder - file 20160313_92ee14238e2c8f39a670501583b56705.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d59d548089eab473483eb071a45171d7f1dd75e7ac0b0a89af26813fdccff68e"

  strings:
    $s1  = "var RP = true  , oYlI = MUX[7] + MUX[9] + MUX[11];" fullword ascii
    $s2  = "return ualBYEq[0] + ualBYEq[2] + ualBYEq[4] + \".F\" + ualBYEq[7] + ualBYEq[9] + ualBYEq[12] + ualBYEq[14];" fullword ascii
    $s3  = "OdkYh.open(qFgYb,xphkR,false);" fullword ascii
    $s4  = "var ualBYEq = \"Sc focvwgV r YcZDWXbFe ipting HVhgnTS ncb ile lXnwEGZSCMudIK System Jv KshkB Obj rWhUZH ect ncruhPC\".split(\" " ascii
    $s5  = "var MUX = (\"2.XMLHTTP NchXctn pIZMX XML ream St KDlorcSr AD uJqxzgH O hDzb D\").split(\" \");" fullword ascii
    $s6  = "function atxtwyg(fkOF,FsQVF) {" fullword ascii
    $s7  = "function IjVC(jQLez,VjTjc) {" fullword ascii
    $s8  = "function btZk(NYVix) {" fullword ascii
    $s9  = "return raPyl.status;" fullword ascii
    $s10 = "function gVJXYae(lvMK) {" fullword ascii
    $s11 = "function MtkEucrCL() {" fullword ascii
    $s12 = "RZL = f; break; " fullword ascii
    $s13 = "return RtBIsi.position=444-444;" fullword ascii
    $s14 = "function oJmM(PhsfX) {" fullword ascii
    $s15 = "function byiXSimdS(dXrSFLSWWAQ) {" fullword ascii
    $s16 = "return fkOF.ExpandEnvironmentStrings(FsQVF);" fullword ascii
    $s17 = "function FvrDilfX() {" fullword ascii
    $s18 = "return atxtwyg(Ni,rHwCr[200-194]+rHwCr[748-741]+rHwCr[769-761]);" fullword ascii
    $s19 = "return hID.size;" fullword ascii
    $s20 = "return new ActiveXObject(xgVezk);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}