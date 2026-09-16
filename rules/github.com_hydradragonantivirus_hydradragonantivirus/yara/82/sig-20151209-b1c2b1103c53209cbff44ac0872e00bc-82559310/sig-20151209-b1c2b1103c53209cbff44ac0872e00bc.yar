rule sig_20151209_b1c2b1103c53209cbff44ac0872e00bc {
  meta:
    description = "datamaliciousorder - file 20151209_b1c2b1103c53209cbff44ac0872e00bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b94f9eb901b002b8b49503713d7fff970be5d4713692fb6b903ca447f04d28c"

  strings:
    $s1  = "function UmEQwdq(NEIEnGFFMbqJzoVHSjTRzzQOWXjTaIKdusxp) {return !isNaN(parseFloat(NEIEnGFFMbqJzoVHSjTRzzQOWXjTaIKdusxp)) && isFin" ascii
    $s2  = "function UmEQwdq(NEIEnGFFMbqJzoVHSjTRzzQOWXjTaIKdusxp) {return !isNaN(parseFloat(NEIEnGFFMbqJzoVHSjTRzzQOWXjTaIKdusxp)) && isFin" ascii
    $s3  = "function PAPaJ(muJdUPoReMF,fknMJSLUdecFb,AykEXkur){ouPR=parseInt(muJdUPoReMF,fknMJSLUdecFb);LghfX=ouPR.toString(AykEXkur);return" ascii
    $s4  = "function AeKzgOedYfG(kCkJnVMO,ScUPFh){return kCkJnVMO.split(ScUPFh)}" fullword ascii
    $s5  = "function MQgDrtMALVhruregNvWnZUKyWoRhFTnRqtAXkKLNgtdUAYTGHMZUva(yFmbATkhBxZrn,fhXZwYAzqEmMHW){ return MGnPD[PAPaJ(yFmbATkhBxZrn[" ascii
    $s6  = " LghfX;}function thNZsJhsBWPoEaz(YWWEHijjjrghVQmsI){eval(YWWEHijjjrghVQmsI)}" fullword ascii
    $s7  = "function xuOThEhzqExpRqtRw(TFNoH){xDCtNxAZgxD= '';for(MqHAjwSalTy=(-768+768)/482; MqHAjwSalTy < (941+777)/859; MqHAjwSalTy++) {w" ascii
    $s8  = "uKjibDIR[MqHAjwSalTy]=(-169+169)/975; while(true) { if(wuKjibDIR[MqHAjwSalTy] > TFNoH[MqHAjwSalTy].length-(17+637)/654) { break;" ascii
    $s9  = "function MQgDrtMALVhruregNvWnZUKyWoRhFTnRqtAXkKLNgtdUAYTGHMZUva(yFmbATkhBxZrn,fhXZwYAzqEmMHW){ return MGnPD[PAPaJ(yFmbATkhBxZrn[" ascii
    $s10 = "function xuOThEhzqExpRqtRw(TFNoH){xDCtNxAZgxD= '';for(MqHAjwSalTy=(-768+768)/482; MqHAjwSalTy < (941+777)/859; MqHAjwSalTy++) {w" ascii
    $s11 = "}} return xDCtNxAZgxD}" fullword ascii
    $s12 = "function PAPaJ(muJdUPoReMF,fknMJSLUdecFb,AykEXkur){ouPR=parseInt(muJdUPoReMF,fknMJSLUdecFb);LghfX=ouPR.toString(AykEXkur);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}