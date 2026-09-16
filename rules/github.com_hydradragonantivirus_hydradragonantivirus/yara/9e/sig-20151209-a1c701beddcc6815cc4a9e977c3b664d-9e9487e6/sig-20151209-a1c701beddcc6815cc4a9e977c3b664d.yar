rule sig_20151209_a1c701beddcc6815cc4a9e977c3b664d {
  meta:
    description = "datamaliciousorder - file 20151209_a1c701beddcc6815cc4a9e977c3b664d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "701e969ef750d66b1f07f2413f05a03bf92f2af1192e7d50530daccb63548db2"

  strings:
    $s1  = "function dcuQdcL(JOLpHxLFGbPRYAIZHlQFdMlNpgWwPBenjIDm) {return !isNaN(parseFloat(JOLpHxLFGbPRYAIZHlQFdMlNpgWwPBenjIDm)) && isFin" ascii
    $s2  = "function dcuQdcL(JOLpHxLFGbPRYAIZHlQFdMlNpgWwPBenjIDm) {return !isNaN(parseFloat(JOLpHxLFGbPRYAIZHlQFdMlNpgWwPBenjIDm)) && isFin" ascii
    $s3  = "function VZnxO(hBqEYbNrhpc,KeiBDAWXLuRLO,qgHjrDus){nwqF=parseInt(hBqEYbNrhpc,KeiBDAWXLuRLO);HNXcW=nwqF.toString(qgHjrDus);return" ascii
    $s4  = "function VZnxO(hBqEYbNrhpc,KeiBDAWXLuRLO,qgHjrDus){nwqF=parseInt(hBqEYbNrhpc,KeiBDAWXLuRLO);HNXcW=nwqF.toString(qgHjrDus);return" ascii
    $s5  = "function GSFKRDIkQNTAzCHhzmvcIYGBvkPRLmoEzNJnmLWYosBqoxxUnLeOOu(udMVuEgobqCMA,EgWcmNyuSLFSbU){ return DsGKp[VZnxO(udMVuEgobqCMA[" ascii
    $s6  = "function GSFKRDIkQNTAzCHhzmvcIYGBvkPRLmoEzNJnmLWYosBqoxxUnLeOOu(udMVuEgobqCMA,EgWcmNyuSLFSbU){ return DsGKp[VZnxO(udMVuEgobqCMA[" ascii
    $s7  = "function KqcYyWQakJJOCiFHk(eGwbQ){hHMVISVhYaQ= '';for(YIkgTokQEoI=(-918+918)/11; YIkgTokQEoI < (1138+834)/986; YIkgTokQEoI++) {D" ascii
    $s8  = "hBvUfLDs[YIkgTokQEoI]=(-982+982)/945; while(true) { if(DhBvUfLDs[YIkgTokQEoI] > eGwbQ[YIkgTokQEoI].length-(717+125)/842) { break" ascii
    $s9  = "function SzakMMqUpVz(YsBVdmrR,EynBtT){return YsBVdmrR.split(EynBtT)}" fullword ascii
    $s10 = "function KqcYyWQakJJOCiFHk(eGwbQ){hHMVISVhYaQ= '';for(YIkgTokQEoI=(-918+918)/11; YIkgTokQEoI < (1138+834)/986; YIkgTokQEoI++) {D" ascii
    $s11 = " HNXcW;}function WFiQvOWdBfBVwUK(LaqYHXpMdpzBmWbeZ){eval(LaqYHXpMdpzBmWbeZ)}" fullword ascii
    $s12 = "}} return hHMVISVhYaQ}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}