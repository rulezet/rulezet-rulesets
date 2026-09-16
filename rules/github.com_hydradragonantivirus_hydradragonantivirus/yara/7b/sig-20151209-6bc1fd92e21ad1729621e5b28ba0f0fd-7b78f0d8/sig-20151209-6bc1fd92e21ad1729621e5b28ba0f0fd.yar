rule sig_20151209_6bc1fd92e21ad1729621e5b28ba0f0fd {
  meta:
    description = "datamaliciousorder - file 20151209_6bc1fd92e21ad1729621e5b28ba0f0fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "775306babac727d33825f58251f5c651241870ca0a82eb95ac9c806925101679"

  strings:
    $s1  = "function VQoNJSL(oeeSemXFFkztVSFgFQoipUKsdgUMXDEidysP) {return !isNaN(parseFloat(oeeSemXFFkztVSFgFQoipUKsdgUMXDEidysP)) && isFin" ascii
    $s2  = "function VQoNJSL(oeeSemXFFkztVSFgFQoipUKsdgUMXDEidysP) {return !isNaN(parseFloat(oeeSemXFFkztVSFgFQoipUKsdgUMXDEidysP)) && isFin" ascii
    $s3  = "function KyUotrCKfMfuWPHBH(qGUFe){dMhMRReIkcI= '';for(EvhsyVSzAjW=(-380+380)/238; EvhsyVSzAjW < (525+487)/506; EvhsyVSzAjW++) {x" ascii
    $s4  = "function TovKG(MtDSLaduHmx,JdtKKYgDuRXml,wkkZEFAT){hvXd=parseInt(MtDSLaduHmx,JdtKKYgDuRXml);Lvtbt=hvXd.toString(wkkZEFAT);return" ascii
    $s5  = "++;}} return dMhMRReIkcI}" fullword ascii
    $s6  = "function TovKG(MtDSLaduHmx,JdtKKYgDuRXml,wkkZEFAT){hvXd=parseInt(MtDSLaduHmx,JdtKKYgDuRXml);Lvtbt=hvXd.toString(wkkZEFAT);return" ascii
    $s7  = "function RDDUvjNgxQfUnICkMzAqyMutrLGdAWlPdMsxgIVTLIUIqssTSPHifb(oNMXjwomBKTnS,PnRdjdsCuZYUvK){ return PxMIf[TovKG(oNMXjwomBKTnS[" ascii
    $s8  = "favqbBaV[EvhsyVSzAjW]=(-374+374)/738; while(true) { if(xfavqbBaV[EvhsyVSzAjW] > qGUFe[EvhsyVSzAjW].length-(-295+668)/373) { brea" ascii
    $s9  = " Lvtbt;}function rQetFgJxxlCyZAE(NqshhynTLGnJhwoHl){eval(NqshhynTLGnJhwoHl)}" fullword ascii
    $s10 = "function KyUotrCKfMfuWPHBH(qGUFe){dMhMRReIkcI= '';for(EvhsyVSzAjW=(-380+380)/238; EvhsyVSzAjW < (525+487)/506; EvhsyVSzAjW++) {x" ascii
    $s11 = "function RDDUvjNgxQfUnICkMzAqyMutrLGdAWlPdMsxgIVTLIUIqssTSPHifb(oNMXjwomBKTnS,PnRdjdsCuZYUvK){ return PxMIf[TovKG(oNMXjwomBKTnS[" ascii
    $s12 = "function saaeTZXFwJT(CXEEXrUJ,qLCAdd){return CXEEXrUJ.split(qLCAdd)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}