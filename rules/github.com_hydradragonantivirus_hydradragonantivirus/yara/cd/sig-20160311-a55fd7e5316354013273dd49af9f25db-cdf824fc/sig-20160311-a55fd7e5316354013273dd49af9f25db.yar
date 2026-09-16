rule sig_20160311_a55fd7e5316354013273dd49af9f25db {
  meta:
    description = "datamaliciousorder - file 20160311_a55fd7e5316354013273dd49af9f25db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36166bad12bca9f16c259c2140d742e58a1eb9cb39269aac1c30153c80112224"

  strings:
    $s1  = "var xm = true  , nEoT = bqE[7] + bqE[9] + bqE[11];" fullword ascii
    $s2  = "return pIBMgji[0] + pIBMgji[2] + pIBMgji[4] + \".F\" + pIBMgji[7] + pIBMgji[9] + pIBMgji[12] + pIBMgji[14];" fullword ascii
    $s3  = "var pIBMgji = \"Sc ykNPUyl r RfdlthmeT ipting PEMLWWY DeR ile iixDwuJZgyJmUh System JF laayE Obj zBWaVy ect GvUwByH\".split(\" " ascii
    $s4  = "var bqE = (\"2.XMLHTTP NrBxxaS MAJSe XML ream St aBgaoHWR AD FPquSRU O dYto D\").split(\" \");" fullword ascii
    $s5  = "MYxqR.open(pQyuZ,rSxdN,false);" fullword ascii
    $s6  = "return cfrcfxm" fullword ascii
    $s7  = "function TzQT(pqGIg,XtpYS) {" fullword ascii
    $s8  = "return ZHka.ExpandEnvironmentStrings(hyPcF);" fullword ascii
    $s9  = "function oPxG(MYxqR,rSxdN,pQyuZ) {" fullword ascii
    $s10 = "function rCpVbFs(uHzx) {" fullword ascii
    $s11 = "function jZXohfTV() {" fullword ascii
    $s12 = "return ZkltS.status;" fullword ascii
    $s13 = "function WxVu(iyKWX,bWCfv) {" fullword ascii
    $s14 = "function GHrYBfej(ZlYFh,vNsVBw) {" fullword ascii
    $s15 = "function woYZFwlR(qxf) {" fullword ascii
    $s16 = "Aod = e; break; " fullword ascii
    $s17 = "function MCxQCrupA() {" fullword ascii
    $s18 = "function BZpJ(ZkltS) {" fullword ascii
    $s19 = "return Yfjaez.position=253-253;" fullword ascii
    $s20 = "function TTgC(ocKFk) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}