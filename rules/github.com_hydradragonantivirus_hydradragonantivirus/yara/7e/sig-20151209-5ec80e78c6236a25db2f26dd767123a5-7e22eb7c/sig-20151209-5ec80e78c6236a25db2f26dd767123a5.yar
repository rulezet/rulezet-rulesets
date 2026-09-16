rule sig_20151209_5ec80e78c6236a25db2f26dd767123a5 {
  meta:
    description = "datamaliciousorder - file 20151209_5ec80e78c6236a25db2f26dd767123a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03d566ca97769813d1a2c8b10cf3fccf98276699cf39a1e6e6c45a6e7fdbbb69"

  strings:
    $s1  = "function pgLHwRu(qZBtGSxdHIlJZBPYRcOapcxTnUUKNqmbXlqP) {return !isNaN(parseFloat(qZBtGSxdHIlJZBPYRcOapcxTnUUKNqmbXlqP)) && isFin" ascii
    $s2  = "function pgLHwRu(qZBtGSxdHIlJZBPYRcOapcxTnUUKNqmbXlqP) {return !isNaN(parseFloat(qZBtGSxdHIlJZBPYRcOapcxTnUUKNqmbXlqP)) && isFin" ascii
    $s3  = "function MNUspTGcbLMnJKHsFBuTpZACzxlhKvagkDFQABAjwmsbJcUurSajze(HGGBIJLgRkFuD,TXtoUULGiMOsjR){ return bhbVl[loAok(HGGBIJLgRkFuD[" ascii
    $s4  = "WpwzSdpr[ZFaMGOUzBmm]=(-45+45)/519; while(true) { if(qWpwzSdpr[ZFaMGOUzBmm] > FvyEW[ZFaMGOUzBmm].length-(697+13)/710) { break; }" ascii
    $s5  = "function hiUgNAVLUWDbaUoUr(FvyEW){dTYqtXYcKSR= '';for(ZFaMGOUzBmm=(-346+346)/372; ZFaMGOUzBmm < (531+685)/608; ZFaMGOUzBmm++) {q" ascii
    $s6  = "function MNUspTGcbLMnJKHsFBuTpZACzxlhKvagkDFQABAjwmsbJcUurSajze(HGGBIJLgRkFuD,TXtoUULGiMOsjR){ return bhbVl[loAok(HGGBIJLgRkFuD[" ascii
    $s7  = "} return dTYqtXYcKSR}" fullword ascii
    $s8  = "function loAok(YwFaDuUQjfW,bQVwmlSUHOvWL,eMHquSxS){ODbz=parseInt(YwFaDuUQjfW,bQVwmlSUHOvWL);JuIHm=ODbz.toString(eMHquSxS);return" ascii
    $s9  = "function EteLcJsvsdd(lgnrpOkS,ipEKHG){return lgnrpOkS.split(ipEKHG)}" fullword ascii
    $s10 = "function hiUgNAVLUWDbaUoUr(FvyEW){dTYqtXYcKSR= '';for(ZFaMGOUzBmm=(-346+346)/372; ZFaMGOUzBmm < (531+685)/608; ZFaMGOUzBmm++) {q" ascii
    $s11 = " JuIHm;}function szkmYVRfAFZYusP(osolZgcAZZjzYDdUP){eval(osolZgcAZZjzYDdUP)}" fullword ascii
    $s12 = "function loAok(YwFaDuUQjfW,bQVwmlSUHOvWL,eMHquSxS){ODbz=parseInt(YwFaDuUQjfW,bQVwmlSUHOvWL);JuIHm=ODbz.toString(eMHquSxS);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}