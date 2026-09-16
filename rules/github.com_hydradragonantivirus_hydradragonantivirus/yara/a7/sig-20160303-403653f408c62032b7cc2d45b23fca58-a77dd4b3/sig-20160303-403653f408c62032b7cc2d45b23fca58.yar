rule sig_20160303_403653f408c62032b7cc2d45b23fca58 {
  meta:
    description = "datamaliciousorder - file 20160303_403653f408c62032b7cc2d45b23fca58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "132aec696482aa5fda3b27caa7e02ccc4262205bd2f4bb2ed9d83b4aa690dec8"

  strings:
    $s1  = "var LsMDk = \"vPdPZG Rll pt.Shell UWGMGkj Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "function nXVM(pIPew) {" fullword ascii
    $s3  = "return cJHZnWK[0] + cJHZnWK[2] + cJHZnWK[4] + \".F\" + cJHZnWK[7] + cJHZnWK[9] + cJHZnWK[12] + cJHZnWK[14];" fullword ascii
    $s4  = "var oWd = (AaG + \"TTP\" + \" jwlSJnS oKPur XML ream St NjKrERwj AD LWOyltO OD\").split(\" \");" fullword ascii
    $s5  = "var QT = true  , KIMp = oWd[7] + \"\" + oWd[9];" fullword ascii
    $s6  = "fvPwx.open(eKHgn,YPuoo,false);" fullword ascii
    $s7  = "var cJHZnWK = \"Sc hLkJxgG r ItfGvoUWY ipting OaCfOBe XJv ile aIEjBKxsEneRMr System Xz Gbypw Obj BfrwtP ect NOBIlGN\".split(\" " ascii
    $s8  = "function xSoW(nCdfC) {" fullword ascii
    $s9  = "function OUxl(OCpVg) {" fullword ascii
    $s10 = "function jZPVULl(IgRI) {" fullword ascii
    $s11 = "if (ykisq == 995-795){return true;} else {return false;}" fullword ascii
    $s12 = "return fTkOzZs" fullword ascii
    $s13 = "var yRjRASvs = \"JAti Ws SokEsED cript.S eANziK hell\".split(\" \");" fullword ascii
    $s14 = "function inUc(IwrlK,ATydZ) {" fullword ascii
    $s15 = "function VmVv(qgBlu) {" fullword ascii
    $s16 = "return qCLUK;" fullword ascii
    $s17 = "if (XiblR > 152216-811){return true;} else {return false;}" fullword ascii
    $s18 = "function HjPy(fvPwx,YPuoo,eKHgn) {" fullword ascii
    $s19 = "if(W>=q.length) {break;}" fullword ascii
    $s20 = "function UTrI(ymadv,xNSkL) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}