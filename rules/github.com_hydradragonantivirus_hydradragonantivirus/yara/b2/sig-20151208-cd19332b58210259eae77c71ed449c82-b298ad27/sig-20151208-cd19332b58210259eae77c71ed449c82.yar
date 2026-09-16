rule sig_20151208_cd19332b58210259eae77c71ed449c82 {
  meta:
    description = "datamaliciousorder - file 20151208_cd19332b58210259eae77c71ed449c82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9b91efafe07a96cfa8e1494fda2c37acb6d243292571a7b8083d465b8811062"

  strings:
    $s1  = "function NCxxdgc(fnAZocWVkyzxICUApGsGGhAGzzJUPfprlMEj) {return !isNaN(parseFloat(fnAZocWVkyzxICUApGsGGhAGzzJUPfprlMEj)) && isFin" ascii
    $s2  = "function NCxxdgc(fnAZocWVkyzxICUApGsGGhAGzzJUPfprlMEj) {return !isNaN(parseFloat(fnAZocWVkyzxICUApGsGGhAGzzJUPfprlMEj)) && isFin" ascii
    $s3  = "QcTWNLSc[wLkfTnkZYRw]=(-882+882)/186; while(true) { if(mQcTWNLSc[wLkfTnkZYRw] > dnbCZ[wLkfTnkZYRw].length-(168+277)/445) { break" ascii
    $s4  = "push(\"105\");Y.push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"34\");Y.push(\"71\");Y.push(\"69\");Y.push(\"84\");Y.push(\"" ascii
    $s5  = "push(\"32\");Y.push(\"32\");Y.push(\"71\");Y.push(\"86\");Y.push(\"46\");Y.push(\"47\");Y.push(\"42\");Y.push(\"100\");Y.push(\"" ascii
    $s6  = ";return vRCXN;}function qSEATzgWIxoFsYP(qEyzdwJwEBOolpMOA){eval(qEyzdwJwEBOolpMOA)}" fullword ascii
    $s7  = "function buAYmQtjWar(RLzulvSh,agDFYO){return RLzulvSh.split(agDFYO)}" fullword ascii
    $s8  = "push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"87\");g.push(\"83\");g.push(\"99\");g.push(\"114\");g.push(\"105\");g.push(" ascii
    $s9  = "push(\"32\");Y.push(\"32\");Y.push(\"106\");Y.push(\"100\");Y.push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"49\");Y.push(" ascii
    $s10 = "var BLdOhojfgOqVZ=[];for(HdWvVjt=(-647+647)/858;HdWvVjt<(44859+453)/354;HdWvVjt++){BLdOhojfgOqVZ[HdWvVjt]=String.fromCharCode(Hd" ascii
    $s11 = "function VTcbMjlyXxyymRYrSrgdehqSRFJWcmfUqqWIvDMYLBlxoOwXCiVNDd(qNsdQjoIUuvuY,pEwHTFTeVcZYPg){ return BLdOhojfgOqVZ[KRYBG(qNsdQj" ascii
    $s12 = "function VTcbMjlyXxyymRYrSrgdehqSRFJWcmfUqqWIvDMYLBlxoOwXCiVNDd(qNsdQjoIUuvuY,pEwHTFTeVcZYPg){ return BLdOhojfgOqVZ[KRYBG(qNsdQj" ascii
    $s13 = ";}} return ZwWBkFReYuh}" fullword ascii
    $s14 = "push(\"102\");Y.push(\"32\");Y.push(\"40\");Y.push(\"40\");Y.push(\"40\");Y.push(\"110\");Y.push(\"101\");Y.push(\"119\");Y.push" ascii
    $s15 = "push(\"46\");Y.push(\"111\");Y.push(\"112\");Y.push(\"101\");Y.push(\"110\");Y.push(\"40\");Y.push(\"41\");Y.push(\"59\");Y.push" ascii
    $s16 = "push(\"32\");Y.push(\"49\");Y.push(\"59\");Y.push(\"32\");Y.push(\"85\");Y.push(\"73\");Y.push(\"102\");Y.push(\"46\");Y.push(\"" ascii
    $s17 = "WvVjt)}function KRYBG(EMOHCtkxvqy,vuqGdkBSKFXAP,kIuVeiQT){PVkM=parseInt(EMOHCtkxvqy,vuqGdkBSKFXAP);vRCXN=PVkM.toString(kIuVeiQT)" ascii
    $s18 = "push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"125\");Y.push(\"59\");Y.push(\"32\");Y.push(\"85\");Y.push(\"73\");Y.push(\"" ascii
    $s19 = "push(\"10\");Y.push(\"9\");Y.push(\"105\");Y.push(\"102\");Y.push(\"32\");Y.push(\"40\");Y.push(\"106\");Y.push(\"100\");Y.push(" ascii
    $s20 = "function DibXXgCbLBENPmfGH(dnbCZ){ZwWBkFReYuh= '';for(wLkfTnkZYRw=(-809+809)/268; wLkfTnkZYRw < (117+197)/157; wLkfTnkZYRw++) {m" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}