rule sig_20160311_8f4ceaa34360884ae39191d1bbb16103 {
  meta:
    description = "datamaliciousorder - file 20160311_8f4ceaa34360884ae39191d1bbb16103.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3d3bbb0ece550b3dd3112e70cc5049ac57924803cce31c4c6c0c4b5d31f388f"

  strings:
    $s1  = "var me = true  , lktB = MMC[7] + MMC[9] + MMC[11];" fullword ascii
    $s2  = "return nSsLrdt[0] + nSsLrdt[2] + nSsLrdt[4] + \".F\" + nSsLrdt[7] + nSsLrdt[9] + nSsLrdt[12] + nSsLrdt[14];" fullword ascii
    $s3  = "TLbrL.open(HfUvs,aosnr,false);" fullword ascii
    $s4  = "var MMC = (\"2.XMLHTTP SiPUaKx AtXzv XML ream St JsusjXZl AD MqHCEvY O hxnJ D\").split(\" \");" fullword ascii
    $s5  = "var nSsLrdt = \"Sc WLxnCQi r FpfBTnUTR ipting ZVTmAWz bjY ile TKetKxzvdEWCuh System lZ pgqLg Obj ciFiIt ect XVheNyQ\".split(\" " ascii
    $s6  = "function pYzD(pswJp) {" fullword ascii
    $s7  = "function CTgalozc() {" fullword ascii
    $s8  = "function OpneSpeJ(wHeLQ,bRaBPk) {" fullword ascii
    $s9  = "function TDgR(sUkxV) {" fullword ascii
    $s10 = "return Nwdqn.status;" fullword ascii
    $s11 = "function iMKJN(vvfEkm) {" fullword ascii
    $s12 = "return cOFb.responseBody;" fullword ascii
    $s13 = "function ACPlX(ScMBlx) {" fullword ascii
    $s14 = "if (c >= sUkxV.length) {break;}" fullword ascii
    $s15 = "return new ActiveXObject(ScMBlx);" fullword ascii
    $s16 = "return PScR.ExpandEnvironmentStrings(gDsnp);" fullword ascii
    $s17 = "zdK = p; break; " fullword ascii
    $s18 = "if(p>=a.length) {break;}" fullword ascii
    $s19 = "function srMc(Nwdqn) {" fullword ascii
    $s20 = "if (thwxk > 131979-846){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}