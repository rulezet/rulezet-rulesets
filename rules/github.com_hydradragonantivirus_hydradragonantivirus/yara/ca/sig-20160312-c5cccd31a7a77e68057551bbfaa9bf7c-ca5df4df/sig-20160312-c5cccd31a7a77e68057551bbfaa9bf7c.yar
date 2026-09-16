rule sig_20160312_c5cccd31a7a77e68057551bbfaa9bf7c {
  meta:
    description = "datamaliciousorder - file 20160312_c5cccd31a7a77e68057551bbfaa9bf7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "107e56bd92a22da0229b61ad7f4486f7ff6fa2c7c2cffea41ed12dee17422fe3"

  strings:
    $s1  = "return BvvaqSX[0] + BvvaqSX[2] + BvvaqSX[4] + \".F\" + BvvaqSX[7] + BvvaqSX[9] + BvvaqSX[12] + BvvaqSX[14];" fullword ascii
    $s2  = "var xq = true  , EJzL = jkZ[7] + jkZ[9] + jkZ[11];" fullword ascii
    $s3  = "CFtwo.open(UGMKA,QUMoL,false);" fullword ascii
    $s4  = "var BvvaqSX = \"Sc PPOrnQa r NnTfwilFn ipting ZYjFaRG XMP ile NNGMaqtWNwuygE System fZ txGaB Obj HQKueU ect BLzGnAR\".split(\" " ascii
    $s5  = "var jkZ = (\"2.XMLHTTP Gypfnqg yCsov XML ream St YDRSOgrV AD fwwpiqE O YoEP D\").split(\" \");" fullword ascii
    $s6  = "function iDwUp(BnfsbJ) {" fullword ascii
    $s7  = "return cCn.size;" fullword ascii
    $s8  = "function hdAQPmI(zapf,CnNDi) {" fullword ascii
    $s9  = "return CqymTzm" fullword ascii
    $s10 = "function gaxM(LxUnN,pXopn) {" fullword ascii
    $s11 = "if (WLvan > 127000-935){return true;} else {return false;}" fullword ascii
    $s12 = "function FuxC(CSfav) {" fullword ascii
    $s13 = "function GfLM(xmQDu) {" fullword ascii
    $s14 = "OoU = f; break; " fullword ascii
    $s15 = "function ucsk(WLvan) {" fullword ascii
    $s16 = "return uMYc.responseBody;" fullword ascii
    $s17 = "function PcmyYqIk() {" fullword ascii
    $s18 = "function efYEuFPTh(WIdWVDxcGWb) {" fullword ascii
    $s19 = "function nShx(qYMij,CZgHC) {" fullword ascii
    $s20 = "return new ActiveXObject(jNlwru);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}