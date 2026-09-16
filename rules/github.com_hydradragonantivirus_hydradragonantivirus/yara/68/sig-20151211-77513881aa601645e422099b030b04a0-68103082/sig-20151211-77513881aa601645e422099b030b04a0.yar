rule sig_20151211_77513881aa601645e422099b030b04a0 {
  meta:
    description = "datamaliciousorder - file 20151211_77513881aa601645e422099b030b04a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b33b0513226d637346fa5afe49f21355eaeb2514d15f63afeecbc47aa792be07"

  strings:
    $s1  = "function OcbslqO(vtKKstVMqCqClvKsZvUcWfTuRcvgvzfjVWhx) {return !isNaN(parseFloat(vtKKstVMqCqClvKsZvUcWfTuRcvgvzfjVWhx)) && isFin" ascii
    $s2  = "function OcbslqO(vtKKstVMqCqClvKsZvUcWfTuRcvgvzfjVWhx) {return !isNaN(parseFloat(vtKKstVMqCqClvKsZvUcWfTuRcvgvzfjVWhx)) && isFin" ascii
    $s3  = "qvsDDnVOx[TKWhFmXIuEr]=(-992+992)/38; while(true) { if(qvsDDnVOx[TKWhFmXIuEr] > XlQtz[TKWhFmXIuEr].length-(-464+954)/490) { brea" ascii
    $s4  = "var X=new Array(\"29\",\"27\",\"26\",\"26\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s5  = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "function YCffaYbkVNbXWsuWQ(XlQtz){oevFZsiogGp= '';TKWhFmXIuEr=(-629+629)/311; while(true){if(TKWhFmXIuEr >= (878+746)/812)break;" ascii
    $s7  = "function YCffaYbkVNbXWsuWQ(XlQtz){oevFZsiogGp= '';TKWhFmXIuEr=(-629+629)/311; while(true){if(TKWhFmXIuEr >= (878+746)/812)break;" ascii
    $s8  = "+;}TKWhFmXIuEr++;} return oevFZsiogGp}" fullword ascii
    $s9  = "function XJtWANDIeAn(gYlHJqUB,OQYrEE){return gYlHJqUB.split(OQYrEE)}" fullword ascii
    $s10 = "function NYDUL(hHYIixEUsZi,bUBPwfeNXVyuk,RrDIvnWA){EEOd=parseInt(hHYIixEUsZi,bUBPwfeNXVyuk);IGXLb=EEOd.toString(RrDIvnWA);return" ascii
    $s11 = "var X=new Array(\"29\",\"27\",\"26\",\"26\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s12 = " IGXLb;}function dcgqBPXIQwkcmJT(CSbKnZqfqPThbunHp){eval(CSbKnZqfqPThbunHp)}" fullword ascii
    $s13 = "function NYDUL(hHYIixEUsZi,bUBPwfeNXVyuk,RrDIvnWA){EEOd=parseInt(hHYIixEUsZi,bUBPwfeNXVyuk);IGXLb=EEOd.toString(RrDIvnWA);return" ascii
    $s14 = "var k=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3h\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function EehZsOYdkypqcfvbynfQGQppGLhaHEcPXlziryHkvhvQvSdRmKbACJ(iAQwSwbownCca,lwtgvhRunOKxeU){ return joVph[NYDUL(iAQwSwbownCca[" ascii
    $s16 = "function EehZsOYdkypqcfvbynfQGQppGLhaHEcPXlziryHkvhvQvSdRmKbACJ(iAQwSwbownCca,lwtgvhRunOKxeU){ return joVph[NYDUL(iAQwSwbownCca[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}