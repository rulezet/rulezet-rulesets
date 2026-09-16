rule sig_20151211_11ebc9aa9d64aa23eaf3b49aa602cb6f {
  meta:
    description = "datamaliciousorder - file 20151211_11ebc9aa9d64aa23eaf3b49aa602cb6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f804e6db8c15bcf7e84fd0d0467a681186d0e1c50e8d8d0ea49bcc6927fe3e6"

  strings:
    $s1  = "function eljWvta(vWAQmXGYispkBcWYNIBJPAmwCzeyuhmDZBMC) {return !isNaN(parseFloat(vWAQmXGYispkBcWYNIBJPAmwCzeyuhmDZBMC)) && isFin" ascii
    $s2  = "function eljWvta(vWAQmXGYispkBcWYNIBJPAmwCzeyuhmDZBMC) {return !isNaN(parseFloat(vWAQmXGYispkBcWYNIBJPAmwCzeyuhmDZBMC)) && isFin" ascii
    $s3  = "function zCiMkTCxMyLxytGjJPotkLTDKmVhFjysGtZCgpJDajHoWqZTUMnEhs(pnTkhsFeWWGTH,NtkZDdDJCDVltY){ return dsbDu[jfKWA(pnTkhsFeWWGTH[" ascii
    $s4  = "var KI=new Array(\"2b\",\"2a\",\"2d\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\"," ascii
    $s5  = " ASffZ;}function tmkTtmeJHGPrKKf(ilwjirADVRYrUPdur){eval(ilwjirADVRYrUPdur)}" fullword ascii
    $s6  = "function jfKWA(UIlVoYkPcrZ,UYRyhrSCeqaUA,RZjAsJPD){KObu=parseInt(UIlVoYkPcrZ,UYRyhrSCeqaUA);ASffZ=KObu.toString(RZjAsJPD);return" ascii
    $s7  = "XDuWYZYjO[DdOMufgOqdl]=(-919+919)/478; while(true) { if(XDuWYZYjO[DdOMufgOqdl] > JonwC[DdOMufgOqdl].length-(-81+533)/452) { brea" ascii
    $s8  = "function DXqtSWgzqqqGdBnEr(JonwC){QJinLJqZQrB= '';DdOMufgOqdl=(-237+237)/836; while(true){if(DdOMufgOqdl >= (159+367)/263)break;" ascii
    $s9  = "function jfKWA(UIlVoYkPcrZ,UYRyhrSCeqaUA,RZjAsJPD){KObu=parseInt(UIlVoYkPcrZ,UYRyhrSCeqaUA);ASffZ=KObu.toString(RZjAsJPD);return" ascii
    $s10 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "var KI=new Array(\"2b\",\"2a\",\"2d\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"1b\"," ascii
    $s12 = "function DXqtSWgzqqqGdBnEr(JonwC){QJinLJqZQrB= '';DdOMufgOqdl=(-237+237)/836; while(true){if(DdOMufgOqdl >= (159+367)/263)break;" ascii
    $s13 = "function zCiMkTCxMyLxytGjJPotkLTDKmVhFjysGtZCgpJDajHoWqZTUMnEhs(pnTkhsFeWWGTH,NtkZDdDJCDVltY){ return dsbDu[jfKWA(pnTkhsFeWWGTH[" ascii
    $s14 = "function TLYcdwJyUTD(XOoRXBnt,qHSBmy){return XOoRXBnt.split(qHSBmy)}" fullword ascii
    $s15 = "var K=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"4j\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = ";}DdOMufgOqdl++;} return QJinLJqZQrB}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}