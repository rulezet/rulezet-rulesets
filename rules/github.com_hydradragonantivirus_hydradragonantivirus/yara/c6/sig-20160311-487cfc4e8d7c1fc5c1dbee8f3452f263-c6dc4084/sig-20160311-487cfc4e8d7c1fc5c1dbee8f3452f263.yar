rule sig_20160311_487cfc4e8d7c1fc5c1dbee8f3452f263 {
  meta:
    description = "datamaliciousorder - file 20160311_487cfc4e8d7c1fc5c1dbee8f3452f263.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21bf38d8cda09185bf0bdc3771b283982663c60385e5ba6c903d0081179df1ce"

  strings:
    $s1  = "var tw = true  , QZlP = OwI[7] + OwI[9] + OwI[11];" fullword ascii
    $s2  = "return zpxArRe[0] + zpxArRe[2] + zpxArRe[4] + \".F\" + zpxArRe[7] + zpxArRe[9] + zpxArRe[12] + zpxArRe[14];" fullword ascii
    $s3  = "var OwI = (\"2.XMLHTTP BIgpnjH hWizO XML ream St UPbRmXHU AD cITMWFJ O dIpy D\").split(\" \");" fullword ascii
    $s4  = "HntpL.open(HowOd,jkGXI,false);" fullword ascii
    $s5  = "var zpxArRe = \"Sc zvmwRTc r iVAyldCwn ipting hCxgrfO YJp ile dQMRwqjEoupUrn System IW XKSFh Obj dhwxQE ect NhaZJLN\".split(\" " ascii
    $s6  = "if (q >= ioGQw.length) {break;}" fullword ascii
    $s7  = "function HfRw(woiKR) {" fullword ascii
    $s8  = "function NKnn(inlwE) {" fullword ascii
    $s9  = "function CVHGYrM(Azwa) {" fullword ascii
    $s10 = "if (woiKR == 950-750){return true;} else {return false;}" fullword ascii
    $s11 = "return KMb.size;" fullword ascii
    $s12 = "return jBUp.ExpandEnvironmentStrings(hnRwn);" fullword ascii
    $s13 = "function fDxkIQsxC(hZdUexpdRLQ) {" fullword ascii
    $s14 = "function nGsJSijy(KMb) {" fullword ascii
    $s15 = "return Azwa.responseBody;" fullword ascii
    $s16 = "function SEZSj(EhPslz) {" fullword ascii
    $s17 = "return CHiIn.status;" fullword ascii
    $s18 = "return SCLLy;" fullword ascii
    $s19 = "function TYuf(TBDEa,gKnYD) {" fullword ascii
    $s20 = "function odzS(mipvn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}