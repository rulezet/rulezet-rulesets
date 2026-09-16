rule sig_20151209_dfb687c64b35a90f8d4ca7da56625eda {
  meta:
    description = "datamaliciousorder - file 20151209_dfb687c64b35a90f8d4ca7da56625eda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e22553a42d23f1980d6ad1b97b054b153506e110928820e58735a35d9cfc653"

  strings:
    $s1  = "function dkjmNIP(vkQZZfBMJdaQqGGFiuZMUqkFJLYuenPsCdNt) {return !isNaN(parseFloat(vkQZZfBMJdaQqGGFiuZMUqkFJLYuenPsCdNt)) && isFin" ascii
    $s2  = "function dkjmNIP(vkQZZfBMJdaQqGGFiuZMUqkFJLYuenPsCdNt) {return !isNaN(parseFloat(vkQZZfBMJdaQqGGFiuZMUqkFJLYuenPsCdNt)) && isFin" ascii
    $s3  = "function RTWbtvXXEMytRQwKN(CHsbW){LFnBdoyYFPd= '';for(iZSIthcgVKm=(-271+271)/838; iZSIthcgVKm < (1027+719)/873; iZSIthcgVKm++) {" ascii
    $s4  = "function fsNaj(zfsxZlcKpCe,QsDBOMHZOegjR,kmgSzVUz){MOiA=parseInt(zfsxZlcKpCe,QsDBOMHZOegjR);GbOHo=MOiA.toString(kmgSzVUz);return" ascii
    $s5  = "function RTWbtvXXEMytRQwKN(CHsbW){LFnBdoyYFPd= '';for(iZSIthcgVKm=(-271+271)/838; iZSIthcgVKm < (1027+719)/873; iZSIthcgVKm++) {" ascii
    $s6  = "function YRegznCtsELRgyVigxlCyfBnvUOmqBhiKcNYfxySUyPJkWMVYHAaPH(JnDZiKxVywUFV,nynDFiFLrVkvPA){ return iXUPD[fsNaj(JnDZiKxVywUFV[" ascii
    $s7  = "function YRegznCtsELRgyVigxlCyfBnvUOmqBhiKcNYfxySUyPJkWMVYHAaPH(JnDZiKxVywUFV,nynDFiFLrVkvPA){ return iXUPD[fsNaj(JnDZiKxVywUFV[" ascii
    $s8  = "function fsNaj(zfsxZlcKpCe,QsDBOMHZOegjR,kmgSzVUz){MOiA=parseInt(zfsxZlcKpCe,QsDBOMHZOegjR);GbOHo=MOiA.toString(kmgSzVUz);return" ascii
    $s9  = "eEZAovwwE[iZSIthcgVKm]=(-82+82)/46; while(true) { if(eEZAovwwE[iZSIthcgVKm] > CHsbW[iZSIthcgVKm].length-(-168+855)/687) { break;" ascii
    $s10 = "return LFnBdoyYFPd}" fullword ascii
    $s11 = "function bUrABpiQUXt(WLeYVurm,tyweuH){return WLeYVurm.split(tyweuH)}" fullword ascii
    $s12 = " GbOHo;}function DGSUzjrSquXqhbG(OXscsktnopMpQkMqz){eval(OXscsktnopMpQkMqz)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}