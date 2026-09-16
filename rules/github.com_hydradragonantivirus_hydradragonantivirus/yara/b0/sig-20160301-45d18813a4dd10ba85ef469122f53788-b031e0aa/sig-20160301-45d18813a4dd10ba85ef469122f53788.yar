rule sig_20160301_45d18813a4dd10ba85ef469122f53788 {
  meta:
    description = "datamaliciousorder - file 20160301_45d18813a4dd10ba85ef469122f53788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aafaebf183774bd4660daed176cdb0ae7bcc893354571ff9620c885f7faae0c0"

  strings:
    $s1  = "var Vm = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(gAqZs);" fullword ascii
    $s3  = "var BO = true  , prXl = Xdu[7] + \"\" + Xdu[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + wLjnSSo + \".F\" + InDNiMaxQS + IdVcK + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var Xdu = (oiy + \"TTP\" + \" TwsCyGT iXGPr XML ream St kSHTnZoZ AD DjvzoBr OD\").split(\" \");" fullword ascii
    $s6  = "KnnYa.open(pdgYW,HtkqP,false);" fullword ascii
    $s7  = "if (kLJOp == 548-348){return true;} else {return false;}" fullword ascii
    $s8  = "return nmcSQ.status;" fullword ascii
    $s9  = "function GTUu(pFnUP,rxfcf) {" fullword ascii
    $s10 = "function mHjn(nmcSQ) {" fullword ascii
    $s11 = "function AgBQ(TqRoS) {" fullword ascii
    $s12 = "function pvuxeRHyK(gYQDOpieZgk) {" fullword ascii
    $s13 = "function IKbG(kLJOp) {" fullword ascii
    $s14 = "function vrCq(SQttW) {" fullword ascii
    $s15 = "if (((new Date())>0,7178230888)) {" fullword ascii
    $s16 = "return ntkuF;" fullword ascii
    $s17 = "function BoHU(KnnYa,HtkqP,pdgYW) {" fullword ascii
    $s18 = "function WCTCxEFi() {" fullword ascii
    $s19 = "function JjgJ(nmhxx) {" fullword ascii
    $s20 = "function pXJi(jJRJb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}