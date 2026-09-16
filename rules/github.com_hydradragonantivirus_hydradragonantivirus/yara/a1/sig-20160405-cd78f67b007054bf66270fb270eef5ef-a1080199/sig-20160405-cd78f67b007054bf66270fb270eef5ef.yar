rule sig_20160405_cd78f67b007054bf66270fb270eef5ef {
  meta:
    description = "datamaliciousorder - file 20160405_cd78f67b007054bf66270fb270eef5ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f36a6e48cbce4e429fd11507d5856674fc25707263bafe02dfcef42abb8c466b"

  strings:
    $s1  = "var KW = true  , Oodc = gsc[7] + gsc[9] + gsc[11];" fullword ascii
    $s2  = "return mJBxleW[0] + mJBxleW[2] + mJBxleW[4] + \".F\" + mJBxleW[7] + mJBxleW[9] + mJBxleW[12] + mJBxleW[14];" fullword ascii
    $s3  = "var gsc = (\"2.XMLHTTP DkIXkSF qRaAe XML ream St vPrKabbO AD iQKdPrG O inoH D\").split(\" \");" fullword ascii
    $s4  = "XaHK.open(FQjTN,QIqgd,false);" fullword ascii
    $s5  = "function fLYx(gOdlI) {" fullword ascii
    $s6  = "return MdZ.split(BvwhV);" fullword ascii
    $s7  = "if (i >= tqlbB.length) {break;}" fullword ascii
    $s8  = "function uSxQIN(vCPTsQZ) {" fullword ascii
    $s9  = "return pODV[OXqNNe[0]];" fullword ascii
    $s10 = "return new ActiveXObject(YOcF);" fullword ascii
    $s11 = "return pmWlgZI[0];" fullword ascii
    $s12 = "return mpkv;" fullword ascii
    $s13 = "function YoGVYT(eMfZ,jUSygj) {" fullword ascii
    $s14 = "function GaUtDuXV(taIL) {" fullword ascii
    $s15 = "return \"iVASPqoNboeZPS\";" fullword ascii
    $s16 = "return uyUScLi(GF,PjsGB[288-282]+PjsGB[760-753]+PjsGB[356-348]);" fullword ascii
    $s17 = "function TGjL(eQIki) {" fullword ascii
    $s18 = "var YgbjzyD = \"DiGVhH*GqB*pt.S\"+\"hell*sdYKmPC*Scri*\";" fullword ascii
    $s19 = "function GMNLVTHrU(FaTJK) {" fullword ascii
    $s20 = "function mpVdO(PQLbHN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}