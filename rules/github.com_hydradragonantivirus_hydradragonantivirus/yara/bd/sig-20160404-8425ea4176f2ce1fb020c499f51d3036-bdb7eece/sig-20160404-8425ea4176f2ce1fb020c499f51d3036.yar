rule sig_20160404_8425ea4176f2ce1fb020c499f51d3036 {
  meta:
    description = "datamaliciousorder - file 20160404_8425ea4176f2ce1fb020c499f51d3036.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec025da6006da3b698d046aa06a5a3e3fb9646f06ada09a56b11695a64c4cc06"

  strings:
    $s1  = "return OTUdTcg[0] + OTUdTcg[2] + OTUdTcg[4] + \".F\" + OTUdTcg[7] + OTUdTcg[9] + OTUdTcg[12] + OTUdTcg[14];" fullword ascii
    $s2  = "var nn = true  , WfPp = AbC[7] + AbC[9] + AbC[11];" fullword ascii
    $s3  = "var AbC = (\"2.XMLHTTP AaIYxqL kmHJK XML ream St XVBQeCGM AD KjAttGs O KMIn D\").split(\" \");" fullword ascii
    $s4  = "rDKc.open(tlmTi,kGYjQ,false);" fullword ascii
    $s5  = "var OTUdTcg = NWyuk(ytGnWjQQMH+\" \"+\"System iv VsDHI Obj lerahz ect kzkhTWL TWzCc\", \" \");" fullword ascii
    $s6  = "if(f>=v.length) {break;}" fullword ascii
    $s7  = "if (OKyFp > 198768-125){return true;} else {return false;}" fullword ascii
    $s8  = "return luZOdPX;" fullword ascii
    $s9  = "return QUp.split(MBdGy);" fullword ascii
    $s10 = "return \"OXsOVbzePlCqsb\";" fullword ascii
    $s11 = "function gRFgXi(jlEyZeD) {" fullword ascii
    $s12 = "function IXakPdNNy(FyuIxJHVSnv) {" fullword ascii
    $s13 = "function Axnnzhor(XdFw) {" fullword ascii
    $s14 = "function qSTtFqDn(Gke) {" fullword ascii
    $s15 = "return IqMMx;" fullword ascii
    $s16 = "function VSaR(hCTwg,vwhWx) {" fullword ascii
    $s17 = "function MRlE(HizOK) {" fullword ascii
    $s18 = "function WyDi(QUiyJ) {" fullword ascii
    $s19 = "function uthBbFi(toew) {" fullword ascii
    $s20 = "return GKNWh.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}