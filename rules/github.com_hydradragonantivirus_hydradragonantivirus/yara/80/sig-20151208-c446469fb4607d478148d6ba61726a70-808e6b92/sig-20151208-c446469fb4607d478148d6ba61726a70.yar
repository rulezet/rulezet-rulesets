rule sig_20151208_c446469fb4607d478148d6ba61726a70 {
  meta:
    description = "datamaliciousorder - file 20151208_c446469fb4607d478148d6ba61726a70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "384e0a0f985fd9c568a7d13510608d23b9ffbb811455d9f9a21d714fa9a8ad15"

  strings:
    $s1  = "function mZPTrQQ(UgbkFRjjlQPVDJZzLLnkEdaKNskXWLPIlrWe) {return !isNaN(parseFloat(UgbkFRjjlQPVDJZzLLnkEdaKNskXWLPIlrWe)) && isFin" ascii
    $s2  = "function mZPTrQQ(UgbkFRjjlQPVDJZzLLnkEdaKNskXWLPIlrWe) {return !isNaN(parseFloat(UgbkFRjjlQPVDJZzLLnkEdaKNskXWLPIlrWe)) && isFin" ascii
    $s3  = "function szikfknUsBeecJHHtrSdwIwMbqmDzzpZEGZPkkJWCrIeHZYxygEPLT(MUwWNMJMBCzYb,aOuqXxcBOTuggm){ return NdXEpwixDIesB[NWbVC(MUwWNM" ascii
    $s4  = "XzrfNb)}function NWbVC(UaDdzmbVLJj,XKUXHQmTKdDvn,dxVAOHHz){tjCB=parseInt(UaDdzmbVLJj,XKUXHQmTKdDvn);IpHzX=tjCB.toString(dxVAOHHz" ascii
    $s5  = "function PEhMpENeFyBArMWhE(tbTxv){iANSpLRQuAO= '';for(oaSHoKDzhPR=(-451+451)/125; oaSHoKDzhPR < (1278+620)/949; oaSHoKDzhPR++) {" ascii
    $s6  = "function PEhMpENeFyBArMWhE(tbTxv){iANSpLRQuAO= '';for(oaSHoKDzhPR=(-451+451)/125; oaSHoKDzhPR < (1278+620)/949; oaSHoKDzhPR++) {" ascii
    $s7  = "push(\"13\");U.push(\"10\");U.push(\"118\");U.push(\"97\");U.push(\"114\");U.push(\"32\");U.push(\"104\");U.push(\"70\");U.push(" ascii
    $s8  = "function szikfknUsBeecJHHtrSdwIwMbqmDzzpZEGZPkkJWCrIeHZYxygEPLT(MUwWNMJMBCzYb,aOuqXxcBOTuggm){ return NdXEpwixDIesB[NWbVC(MUwWNM" ascii
    $s9  = "push(\"68\");G.push(\"67\");G.push(\"41\");G.push(\"59\");G.push(\"13\");G.push(\"10\");G.push(\"118\");G.push(\"97\");G.push(\"" ascii
    $s10 = "fYzUAocMj[oaSHoKDzhPR]=(-605+605)/256; while(true) { if(fYzUAocMj[oaSHoKDzhPR] > tbTxv[oaSHoKDzhPR].length-(444+290)/734) { brea" ascii
    $s11 = "push(\"32\");G.push(\"70\");G.push(\"70\");G.push(\"67\");G.push(\"32\");G.push(\"61\");G.push(\"32\");G.push(\"72\");G.push(\"1" ascii
    $s12 = "push(\"45\");G.push(\"105\");G.push(\"110\");G.push(\"99\");G.push(\"108\");G.push(\"117\");G.push(\"100\");G.push(\"101\");G.pu" ascii
    $s13 = "push(\"108\");U.push(\"115\");U.push(\"101\");U.push(\"41\");U.push(\"59\");U.push(\"32\");U.push(\"122\");U.push(\"86\");U.push" ascii
    $s14 = "push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"32\");U.push(\"125\");U.push(\"59\");U.push(\"32\");U.push(\"13\");U.push(\"" ascii
    $s15 = "push(\"116\");U.push(\"101\");U.push(\"40\");U.push(\"122\");U.push(\"86\");U.push(\"46\");U.push(\"114\");U.push(\"101\");U.pus" ascii
    $s16 = "push(\"70\");U.push(\"118\");U.push(\"46\");U.push(\"112\");U.push(\"111\");U.push(\"115\");U.push(\"105\");U.push(\"116\");U.pu" ascii
    $s17 = ");return IpHzX;}function TnQALQdIAViMWXj(ZGltUovoXIuXJpEvK){eval(ZGltUovoXIuXJpEvK)}" fullword ascii
    $s18 = "function RWvPgZHyUYW(VgtAYnvB,nvQPKi){return VgtAYnvB.split(nvQPKi)}" fullword ascii
    $s19 = "push(\"122\");U.push(\"59\");U.push(\"32\");U.push(\"98\");U.push(\"114\");U.push(\"101\");U.push(\"97\");U.push(\"107\");U.push" ascii
    $s20 = "+;}} return iANSpLRQuAO}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}