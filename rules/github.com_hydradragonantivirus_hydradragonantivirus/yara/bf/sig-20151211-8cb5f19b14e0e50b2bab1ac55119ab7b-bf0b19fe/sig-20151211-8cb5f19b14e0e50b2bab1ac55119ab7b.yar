rule sig_20151211_8cb5f19b14e0e50b2bab1ac55119ab7b {
  meta:
    description = "datamaliciousorder - file 20151211_8cb5f19b14e0e50b2bab1ac55119ab7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "363f499b6d56c75a8452b436f721b96c0dc0d7543a62fd1b53c28980e3d4899e"

  strings:
    $s1  = "function UfpQoVw(WtykpMZjmosvdERPCILzTcvesfoqfRIvYBhm) {return !isNaN(parseFloat(WtykpMZjmosvdERPCILzTcvesfoqfRIvYBhm)) && isFin" ascii
    $s2  = "function UfpQoVw(WtykpMZjmosvdERPCILzTcvesfoqfRIvYBhm) {return !isNaN(parseFloat(WtykpMZjmosvdERPCILzTcvesfoqfRIvYBhm)) && isFin" ascii
    $s3  = "var s=new Array(\"2d\",\"26\",\"29\",\"28\",\"28\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s4  = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "function YSglZRrwjlVOzNXrXzmvSYgHLOcOGrenHsYbyTziCwiKOwKFxkEvzt(cRCowKNhkzPBd,tloPmFDPOGtrHj){ return Ndhch[ssudD(cRCowKNhkzPBd[" ascii
    $s6  = "function LNcdiAUeRDGnscfVK(vLIPr){kkmxjoMvKKH= '';vURZLBplQky=(-927+927)/866; while(true){if(vURZLBplQky >= (787+339)/563)break;" ascii
    $s7  = "var s=new Array(\"2d\",\"26\",\"29\",\"28\",\"28\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "rjtCfkUDK[vURZLBplQky]=(-139+139)/185; while(true) { if(rjtCfkUDK[vURZLBplQky] > vLIPr[vURZLBplQky].length-(-212+713)/501) { bre" ascii
    $s9  = "var N=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3i\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = " UdlnV;}function bHzUbACpqHTMokM(fnBPQxpAPClbZinqr){eval(fnBPQxpAPClbZinqr)}" fullword ascii
    $s11 = "function YSglZRrwjlVOzNXrXzmvSYgHLOcOGrenHsYbyTziCwiKOwKFxkEvzt(cRCowKNhkzPBd,tloPmFDPOGtrHj){ return Ndhch[ssudD(cRCowKNhkzPBd[" ascii
    $s12 = "function OylHvIAAXAu(QUKhbRan,UZfNHh){return QUKhbRan.split(UZfNHh)}" fullword ascii
    $s13 = "function LNcdiAUeRDGnscfVK(vLIPr){kkmxjoMvKKH= '';vURZLBplQky=(-927+927)/866; while(true){if(vURZLBplQky >= (787+339)/563)break;" ascii
    $s14 = "function ssudD(RmRUPXIHsbn,MjLtMmkMPiZpe,xCNwZhEI){ZTKK=parseInt(RmRUPXIHsbn,MjLtMmkMPiZpe);UdlnV=ZTKK.toString(xCNwZhEI);return" ascii
    $s15 = "function ssudD(RmRUPXIHsbn,MjLtMmkMPiZpe,xCNwZhEI){ZTKK=parseInt(RmRUPXIHsbn,MjLtMmkMPiZpe);UdlnV=ZTKK.toString(xCNwZhEI);return" ascii
    $s16 = ";}vURZLBplQky++;} return kkmxjoMvKKH}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}