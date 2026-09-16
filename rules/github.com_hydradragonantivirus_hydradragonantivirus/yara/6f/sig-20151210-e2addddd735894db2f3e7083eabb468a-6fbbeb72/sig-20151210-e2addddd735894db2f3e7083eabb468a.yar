rule sig_20151210_e2addddd735894db2f3e7083eabb468a {
  meta:
    description = "datamaliciousorder - file 20151210_e2addddd735894db2f3e7083eabb468a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3a946a73875472ac753f4a176d7148d48b013f40cce5ad076e7cf867ec8ecb9"

  strings:
    $s1  = "function EtHtFkJPTsVJNMfKO(fmHzh){JaBOQmBBrUK= '';for(HZwIqAOWbhs=(-280+280)/803; HZwIqAOWbhs < (784+944)/864; HZwIqAOWbhs++) {x" ascii
    $s2  = "function raGOR(yCHECSEXhRS,hQncnMjTpBJBq,tMlgGLUC){NlpV=parseInt(yCHECSEXhRS,hQncnMjTpBJBq);CGrtM=NlpV.toString(tMlgGLUC);return" ascii
    $s3  = "zUKDDAmB[HZwIqAOWbhs]=(-822+822)/42; while(true) { if(xzUKDDAmB[HZwIqAOWbhs] > fmHzh[HZwIqAOWbhs].length-(-601+864)/263) { break" ascii
    $s4  = "function EtHtFkJPTsVJNMfKO(fmHzh){JaBOQmBBrUK= '';for(HZwIqAOWbhs=(-280+280)/803; HZwIqAOWbhs < (784+944)/864; HZwIqAOWbhs++) {x" ascii
    $s5  = "}} return JaBOQmBBrUK}" fullword ascii
    $s6  = "function rmctukpQGuI(nbxQCyDq,EDUPHr){return nbxQCyDq.split(EDUPHr)}" fullword ascii
    $s7  = " CGrtM;}function UsMnGxnIUOzAuge(CXQZaAftjVmDODBvp){eval(CXQZaAftjVmDODBvp)}" fullword ascii
    $s8  = "function raGOR(yCHECSEXhRS,hQncnMjTpBJBq,tMlgGLUC){NlpV=parseInt(yCHECSEXhRS,hQncnMjTpBJBq);CGrtM=NlpV.toString(tMlgGLUC);return" ascii
    $s9  = "function ywsroTn(lycFzdvHruexRCagIFWnSeRwjIehDVMzcYPs) {return !isNaN(parseFloat(lycFzdvHruexRCagIFWnSeRwjIehDVMzcYPs)) && isFin" ascii
    $s10 = "function ywsroTn(lycFzdvHruexRCagIFWnSeRwjIehDVMzcYPs) {return !isNaN(parseFloat(lycFzdvHruexRCagIFWnSeRwjIehDVMzcYPs)) && isFin" ascii
    $s11 = "function eiAssXZVgtJbnkHvayvkZCGXLTMjuihiGMElGhkrCcIsIAhIixSHUJ(OqmNxIxQFpHZO,twGMmnxKQkJcar){ return msUrn[raGOR(OqmNxIxQFpHZO[" ascii
    $s12 = "function eiAssXZVgtJbnkHvayvkZCGXLTMjuihiGMElGhkrCcIsIAhIixSHUJ(OqmNxIxQFpHZO,twGMmnxKQkJcar){ return msUrn[raGOR(OqmNxIxQFpHZO[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}