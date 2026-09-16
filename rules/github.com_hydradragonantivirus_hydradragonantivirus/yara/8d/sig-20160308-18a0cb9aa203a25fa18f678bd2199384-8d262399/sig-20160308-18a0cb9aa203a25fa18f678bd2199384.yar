rule sig_20160308_18a0cb9aa203a25fa18f678bd2199384 {
  meta:
    description = "datamaliciousorder - file 20160308_18a0cb9aa203a25fa18f678bd2199384.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b5996736f50f141850374fdd3d274f3291939a2b04fff4dd00d9784b5f00697"

  strings:
    $s1  = "var jF = true  , TyKG = vgt[7] + vgt[9] + vgt[11];" fullword ascii
    $s2  = "return DAZhaKA[0] + DAZhaKA[2] + DAZhaKA[4] + \".F\" + DAZhaKA[7] + DAZhaKA[9] + DAZhaKA[12] + DAZhaKA[14];" fullword ascii
    $s3  = "oGbMA.open(eeBZD,TZDni,false);" fullword ascii
    $s4  = "var vgt = (\"2.XMLHTTP bGFfyXz gCCvF XML ream St dMDcbJAe AD ArtZMNZ O xudw D\").split(\" \");" fullword ascii
    $s5  = "var DAZhaKA = \"Sc MJyzody r vlfBHReSC ipting exJxKjj gdH ile UfhHZYYAUERTim System kg tWTag Obj AFFBff ect ZozeJsG\".split(\" " ascii
    $s6  = "return DMng.responseBody;" fullword ascii
    $s7  = "if (xFXrb == 512-312){return true;} else {return false;}" fullword ascii
    $s8  = "function qszd(YbYfl) {" fullword ascii
    $s9  = "function IpVmLvh(DMng) {" fullword ascii
    $s10 = "function kXnq(Sryne) {" fullword ascii
    $s11 = "function BqqIN(ZDfXLJ) {" fullword ascii
    $s12 = "function ITJR(oGbMA,TZDni,eeBZD) {" fullword ascii
    $s13 = "if (X >= jABYj.length) {break;}" fullword ascii
    $s14 = "function zsJA(sOyJS) {" fullword ascii
    $s15 = "return dlQSMYF" fullword ascii
    $s16 = "function NNPl(OyheC) {" fullword ascii
    $s17 = "return new ActiveXObject(ZDfXLJ);" fullword ascii
    $s18 = "hCW = M; break; " fullword ascii
    $s19 = "if(M>=U.length) {break;}" fullword ascii
    $s20 = "return mb.ExpandEnvironmentStrings(JkGKV[6]+JkGKV[7]+JkGKV[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}