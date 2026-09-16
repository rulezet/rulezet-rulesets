rule sig_20160310_73c8ff30cbd8091c5ecbf71b67814e8e {
  meta:
    description = "datamaliciousorder - file 20160310_73c8ff30cbd8091c5ecbf71b67814e8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32bf0014036e315172fee299ef8456307a9016d568f6df3121b09ef091d5dc2a"

  strings:
    $s1  = "var xn = true  , YbbS = ANl[7] + ANl[9] + ANl[11];" fullword ascii
    $s2  = "return lUplpgo[0] + lUplpgo[2] + lUplpgo[4] + \".F\" + lUplpgo[7] + lUplpgo[9] + lUplpgo[12] + lUplpgo[14];" fullword ascii
    $s3  = "var lUplpgo = \"Sc hKTkbwT r yYRQLhcJF ipting uyazgcX BDK ile ziMzBRorvMBMqE System ex gojom Obj udlXvL ect pRDmJJj\".split(\" " ascii
    $s4  = "var ANl = (\"2.XMLHTTP DqwUGbK XzmJh XML ream St VctMzxXN AD CGZWkYL O StbR D\").split(\" \");" fullword ascii
    $s5  = "PuRcz.open(OryDi,vNqJG,false);" fullword ascii
    $s6  = "function UJSED(jJqXkT) {" fullword ascii
    $s7  = "function CvnBEyTZS(JtSOG,zYUQk,tZXHw,buoG) {" fullword ascii
    $s8  = "function OrOf(HIAyY) {" fullword ascii
    $s9  = "return DBkEpJh" fullword ascii
    $s10 = "return BsBzjiy(Ch,TdFOd[663-657]+TdFOd[177-170]+TdFOd[182-174]);" fullword ascii
    $s11 = "function pORLI(npXKJn) {" fullword ascii
    $s12 = "function CBaFiqvQ(Opt) {" fullword ascii
    $s13 = "function cgck(dbtgG) {" fullword ascii
    $s14 = "return Iukm.responseBody;" fullword ascii
    $s15 = "if (dbtgG == 446-246){return true;} else {return false;}" fullword ascii
    $s16 = "function BsBzjiy(PxSU,zRuue) {" fullword ascii
    $s17 = "return rUPrC;" fullword ascii
    $s18 = "omC = J; break; " fullword ascii
    $s19 = "function ulZZ(hrrLz) {" fullword ascii
    $s20 = "function OehQ(koDfK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}