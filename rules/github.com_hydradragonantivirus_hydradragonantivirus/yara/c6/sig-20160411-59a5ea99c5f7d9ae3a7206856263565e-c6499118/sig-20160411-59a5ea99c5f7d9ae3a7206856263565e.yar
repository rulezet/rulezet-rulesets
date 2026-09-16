rule sig_20160411_59a5ea99c5f7d9ae3a7206856263565e {
  meta:
    description = "datamaliciousorder - file 20160411_59a5ea99c5f7d9ae3a7206856263565e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c5365b229dd5f3f06b0f378ddd34d38ea1924f3ba2aef0743dd18999892014b"

  strings:
    $s1  = "return qNRSjuT[0] + qNRSjuT[2] + qNRSjuT[4] + \".F\" + qNRSjuT[7] + qNRSjuT[9] + qNRSjuT[12] + qNRSjuT[14];" fullword ascii
    $s2  = "var YHIIuErc = COFF(cYygnxZV[210-209] + cYygnxZV[944-941] + cYygnxZV[913-908] + cYygnxZV[205-199] + cYygnxZV[464-456] + cYygnxZV" ascii
    $s3  = "var RMd = COFF(DLar + \"B.\" + jPj[5]+(339995, jPj[4]));" fullword ascii
    $s4  = "var iT = true  , DLar = jPj[7] + jPj[9] + jPj[11];" fullword ascii
    $s5  = "var YHIIuErc = COFF(cYygnxZV[210-209] + cYygnxZV[944-941] + cYygnxZV[913-908] + cYygnxZV[205-199] + cYygnxZV[464-456] + cYygnxZV" ascii
    $s6  = "KEbb.open(IOEtc,XkaaN,false);" fullword ascii
    $s7  = "var jPj = (\"2.XMLHTTP twKvLij nRxAv XML ream St PPEGJlVe AD hUtAAHt O Hfqk D\").split(\" \");" fullword ascii
    $s8  = "function PLjm(zGUNp) {" fullword ascii
    $s9  = "return NXaURj[jiyP[606-606]]=211-211;" fullword ascii
    $s10 = "function XYCWhM(VYdm,cbijzl) {" fullword ascii
    $s11 = "function EjQGNkd(hxTt,Ejnhu) {" fullword ascii
    $s12 = "pNY = X; break; " fullword ascii
    $s13 = "if(X>=q.length) {break;}" fullword ascii
    $s14 = "function COFF(CcNde) {" fullword ascii
    $s15 = "if (zGUNp > 172254-653){return true;} else {return false;}" fullword ascii
    $s16 = "if (d >= tViig.length) {break;}" fullword ascii
    $s17 = "return \"jOmwMNOnchHJPR\";" fullword ascii
    $s18 = "return WvN.size;" fullword ascii
    $s19 = "function KENEVFA(mhBN) {" fullword ascii
    $s20 = "function DcsqKnrKj(CXUgf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}