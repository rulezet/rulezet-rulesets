rule sig_20160308_51726af92818a3fc47e06f9d167f6bb5 {
  meta:
    description = "datamaliciousorder - file 20160308_51726af92818a3fc47e06f9d167f6bb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e998448f5192d72987039d9754c57eefdd8e8112e7d80ea80da74b0ffd77419"

  strings:
    $s1  = "return zGjGMxo[0] + zGjGMxo[2] + zGjGMxo[4] + \".F\" + zGjGMxo[7] + zGjGMxo[9] + zGjGMxo[12] + zGjGMxo[14];" fullword ascii
    $s2  = "var FA = true  , FtrR = IlB[7] + IlB[9] + IlB[11];" fullword ascii
    $s3  = "var zGjGMxo = \"Sc jQacKal r PVljzayQR ipting jIiZAvt OYU ile YooODsUOGVYwnq System Kc BSqIt Obj SQnGZp ect EowiZlU\".split(\" " ascii
    $s4  = "var IlB = (\"2.XMLHTTP NywKNqT ajppl XML ream St rhfYgdyF AD ljRcpqj O EKGA D\").split(\" \");" fullword ascii
    $s5  = "IJIBd.open(gEmtP,giRIH,false);" fullword ascii
    $s6  = "return new ActiveXObject(XhoFwb);" fullword ascii
    $s7  = "function rAgE(AHtNy) {" fullword ascii
    $s8  = "function VFnL(DvhvH) {" fullword ascii
    $s9  = "function ENYdXUC(XUmV) {" fullword ascii
    $s10 = "return aS.ExpandEnvironmentStrings(LlpWs[6]+LlpWs[7]+LlpWs[8]);" fullword ascii
    $s11 = "return LMZt.responseBody;" fullword ascii
    $s12 = "function HkfKtqU(LMZt) {" fullword ascii
    $s13 = "if (nmglF == 551-351){return true;} else {return false;}" fullword ascii
    $s14 = "if (DvuKU > 182453-727){return true;} else {return false;}" fullword ascii
    $s15 = "function QVEr(gcyka,ZamIp) {" fullword ascii
    $s16 = "return rjRTB;" fullword ascii
    $s17 = "function vfiQ(nmglF) {" fullword ascii
    $s18 = "function FjkP(IJIBd,giRIH,gEmtP) {" fullword ascii
    $s19 = "if(J>=n.length) {break;}" fullword ascii
    $s20 = "function mWcsnkHu(gat) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}