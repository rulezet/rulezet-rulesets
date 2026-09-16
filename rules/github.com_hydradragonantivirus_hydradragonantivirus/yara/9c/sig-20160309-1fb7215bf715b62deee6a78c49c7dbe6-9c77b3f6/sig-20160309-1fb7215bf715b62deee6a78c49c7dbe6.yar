rule sig_20160309_1fb7215bf715b62deee6a78c49c7dbe6 {
  meta:
    description = "datamaliciousorder - file 20160309_1fb7215bf715b62deee6a78c49c7dbe6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41804d4560612fce7f06c38b7f08014dcf687827ce0c21c924c8ca546d064100"

  strings:
    $s1  = "var yK = true  , tuqa = tgf[7] + tgf[9] + tgf[11];" fullword ascii
    $s2  = "return PtgKaoT[0] + PtgKaoT[2] + PtgKaoT[4] + \".F\" + PtgKaoT[7] + PtgKaoT[9] + PtgKaoT[12] + PtgKaoT[14];" fullword ascii
    $s3  = "var PtgKaoT = \"Sc bhAmmsp r iYgoIwFvi ipting ALATnbv pKm ile akLRaySLGrJoWi System IR rtkKN Obj WKcTHv ect JsWPSac\".split(\" " ascii
    $s4  = "var tgf = (\"2.XMLHTTP MYnqxzj DUueO XML ream St dXggQKze AD gkSjreK O aNyY D\").split(\" \");" fullword ascii
    $s5  = "cSRLd.open(dpEDa,YqVor,false);" fullword ascii
    $s6  = "function hKKJ(SrJNf) {" fullword ascii
    $s7  = "function HRNw(PQlXz) {" fullword ascii
    $s8  = "function juqx(saJdV,bsbxp) {" fullword ascii
    $s9  = "function TNCiHTNt(EytnN,DocqFN) {" fullword ascii
    $s10 = "Vvy = p; break; " fullword ascii
    $s11 = "function hRkKTCXR(kzI) {" fullword ascii
    $s12 = "function Oakg(dbMuR) {" fullword ascii
    $s13 = "function noBe(mvqRl) {" fullword ascii
    $s14 = "if (omPQs > 189636-157){return true;} else {return false;}" fullword ascii
    $s15 = "function Oaiy(ajZkD) {" fullword ascii
    $s16 = "function Qvxx(cSRLd,YqVor,dpEDa) {" fullword ascii
    $s17 = "if (P >= mvqRl.length) {break;}" fullword ascii
    $s18 = "function tFYy(omPQs) {" fullword ascii
    $s19 = "return NPAEmHW(RC,LOBnk[521-515]+LOBnk[909-902]+LOBnk[978-970]);" fullword ascii
    $s20 = "function NVEQRgjSm(mVZFB,aEmbZ,pegzr,zWhx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}