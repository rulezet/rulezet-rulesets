rule sig_20151217_ce69982b0caa85b01a660ce5957f79c5 {
  meta:
    description = "datamaliciousorder - file 20151217_ce69982b0caa85b01a660ce5957f79c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79660d33b149b21ad640d20d40bd90b23779616fe1be6f19c24d67d7b286a4a2"

  strings:
    $s1  = ") - 1));while(true){if (GFfKSFZKlSN >= (4982+142)/854){break;}lDoiyjyLx[GFfKSFZKlSN]=Math.round((Math.pow(Math.sin(782), 2) + Ma" ascii
    $s2  = "function yfOyhnfdbobXcKnnB(LqVKU){oOjQyVzYWix= '';GFfKSFZKlSN=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.cos(971), 2" ascii
    $s3  = ".pow(Math.cos(211), 2) - 1)));} lDoiyjyLx[GFfKSFZKlSN]++;}GFfKSFZKlSN++;} return oOjQyVzYWix}" fullword ascii
    $s4  = "th.pow(Math.cos(782), 2) - 1)); while(true) { if(lDoiyjyLx[GFfKSFZKlSN] > LqVKU[GFfKSFZKlSN].length-(-198+840)/642) { break; } i" ascii
    $s5  = "function yfOyhnfdbobXcKnnB(LqVKU){oOjQyVzYWix= '';GFfKSFZKlSN=Math.round((Math.pow(Math.sin(971), 2) + Math.pow(Math.cos(971), 2" ascii
    $s6  = "sNzDnBWTRYXhzqBcSBpAcRmZSJYfzHFVQSoH([LqVKU[GFfKSFZKlSN][lDoiyjyLx[GFfKSFZKlSN]]], Math.round((Math.pow(Math.sin(211), 2) + Math" ascii
    $s7  = "function jpgyYxf(jvbdckVxFhkFMEdDwXmlilLREppmYOcXvdAL) {return !aTMGqjfYZIg(CjhthfAOvilVwAl(jvbdckVxFhkFMEdDwXmlilLREppmYOcXvdAL" ascii
    $s8  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s9  = "q);return MxJFd;}" fullword ascii
    $s10 = "function lmCgtlWyKpvHlPBptesNzDnBWTRYXhzqBcSBpAcRmZSJYfzHFVQSoH(zuDdxRmwVnjrj,TIcCXXfYaEzIXR){ return jPZRfla[XsnAOFiv[AFGLl(zuD" ascii
    $s11 = "function g(FRVZWVXUAOzb,CrqevGOfyRVdXY){FRVZWVXUAOzb.push(CrqevGOfyRVdXY);}" fullword ascii
    $s12 = "function QHJGWrsqeYHa(GncugCxGlUSwZ) {return isFinite(GncugCxGlUSwZ);}" fullword ascii
    $s13 = "function AFGLl(SlxLtgicOuq,KOLiXJFHGNMPF,BgBFBIrq){EWbj=EVqsOwNIygxCLaqzf(SlxLtgicOuq,KOLiXJFHGNMPF);MxJFd=EWbj.toString(BgBFBIr" ascii
    $s14 = "function EVqsOwNIygxCLaqzf(HEAyOvoGEI,NmrQzQjqVV) {return parseInt(HEAyOvoGEI,NmrQzQjqVV);}" fullword ascii
    $s15 = "function a(zAdoIpDbHHlltn,oqaTjAKFRXSYt,PtDooIBtwuu) {zAdoIpDbHHlltn[oqaTjAKFRXSYt]=PtDooIBtwuu;}" fullword ascii
    $s16 = "function lmCgtlWyKpvHlPBptesNzDnBWTRYXhzqBcSBpAcRmZSJYfzHFVQSoH(zuDdxRmwVnjrj,TIcCXXfYaEzIXR){ return jPZRfla[XsnAOFiv[AFGLl(zuD" ascii
    $s17 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s18 = "function jpgyYxf(jvbdckVxFhkFMEdDwXmlilLREppmYOcXvdAL) {return !aTMGqjfYZIg(CjhthfAOvilVwAl(jvbdckVxFhkFMEdDwXmlilLREppmYOcXvdAL" ascii
    $s19 = "function CjhthfAOvilVwAl(qIHPCwXJresaUIkMyjk) {return parseFloat(qIHPCwXJresaUIkMyjk);}" fullword ascii
    $s20 = "function AFGLl(SlxLtgicOuq,KOLiXJFHGNMPF,BgBFBIrq){EWbj=EVqsOwNIygxCLaqzf(SlxLtgicOuq,KOLiXJFHGNMPF);MxJFd=EWbj.toString(BgBFBIr" ascii

  condition:
    uint16(0) == 0x7358 and
    8 of them
}