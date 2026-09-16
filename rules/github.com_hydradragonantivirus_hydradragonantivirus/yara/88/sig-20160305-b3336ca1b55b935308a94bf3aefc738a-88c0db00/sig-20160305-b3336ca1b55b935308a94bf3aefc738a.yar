rule sig_20160305_b3336ca1b55b935308a94bf3aefc738a {
  meta:
    description = "datamaliciousorder - file 20160305_b3336ca1b55b935308a94bf3aefc738a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7083275ffc93dfc41221b1c55f1f4e0abb74a9eeecf7a2c9ea1f4b27bbecfa"

  strings:
    $s1  = "var NXTkp = \"jpDSAk aPO pt.Shell qZquryW Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "fJDEE.open(AdSPy,SvDfv,false);" fullword ascii
    $s3  = "function YuWl(fJDEE,SvDfv,AdSPy) {" fullword ascii
    $s4  = "return jMFzzDA[0] + jMFzzDA[2] + jMFzzDA[4] + \".F\" + jMFzzDA[7] + jMFzzDA[9] + jMFzzDA[12] + jMFzzDA[14];" fullword ascii
    $s5  = "var PK = true  , DIvZ = qja[7] + \"\" + qja[9];" fullword ascii
    $s6  = "var jMFzzDA = \"Sc bzXJHeE r GCkIFAsrv ipting GXQVGze JyM ile zNCtUUJYQNpRjj System Ys iuCHJ Obj jyWaAf ect EjjMlxN\".split(\" " ascii
    $s7  = "function tMpE(CSABO) {" fullword ascii
    $s8  = "function SAnng(ObwXSf) {" fullword ascii
    $s9  = "function ALQHvbLDk(cPMOqpCTnxi) {" fullword ascii
    $s10 = "return jxBmW;" fullword ascii
    $s11 = "function FCol(Omgii,doilz) {" fullword ascii
    $s12 = "function wlfhjvwDu(vUleN,aAVMr,iHrYh) {" fullword ascii
    $s13 = "return So.ExpandEnvironmentStrings(NXTkp[6]);" fullword ascii
    $s14 = "return new ActiveXObject(ObwXSf);" fullword ascii
    $s15 = "return CSABO.status;" fullword ascii
    $s16 = "return oyXfPUY" fullword ascii
    $s17 = "if (TmXdd > 191155-438){return true;} else {return false;}" fullword ascii
    $s18 = "function ublc(HXkhd) {" fullword ascii
    $s19 = "if (ukNyQ == 376-176){return true;} else {return false;}" fullword ascii
    $s20 = "function cIIc(ukNyQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}