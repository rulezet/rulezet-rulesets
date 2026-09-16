rule sig_20151215_6addf6d1fea99d7fc0fe73ab1d18df9f {
  meta:
    description = "datamaliciousorder - file 20151215_6addf6d1fea99d7fc0fe73ab1d18df9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e334d0daa13def5a267578c162cd2ac50d07feea4db0eb0d37432cda0322e8e5"

  strings:
    $s1  = "ath.pow(Math.cos(996), 2) - 1)); while(true) { if(rvDXJAwzG[AMyYbJngvfO] > fBMdE[AMyYbJngvfO].length-(-43+59)/16) { break; } if " ascii
    $s2  = "(Math.cos(663), 2) - 1)));} rvDXJAwzG[AMyYbJngvfO]++;}} return UvYmeuURsrU}" fullword ascii
    $s3  = "function ScKhNUjPkIvvYLCXD(fBMdE){UvYmeuURsrU= K[1836];for(AMyYbJngvfO=Math.round((Math.pow(Math.sin(181), 2) + Math.pow(Math.co" ascii
    $s4  = "function ScKhNUjPkIvvYLCXD(fBMdE){UvYmeuURsrU= K[1836];for(AMyYbJngvfO=Math.round((Math.pow(Math.sin(181), 2) + Math.pow(Math.co" ascii
    $s5  = "RZGU)) {return (String.fromCharCode(KESSeyXpWVsbRZGU) + String.fromCharCode((40796+611)/881));}}" fullword ascii
    $s6  = "function V(KNGTwaNZdCiE,FWdtInKzVXornb){KNGTwaNZdCiE.push(FWdtInKzVXornb);}function x5(KESSeyXpWVsbRZGU){if(hpACMNv(KESSeyXpWVsb" ascii
    $s7  = "function hpACMNv(nOiKiLDCknLYByHnzBJBxoZOrveRyYHpfJZG) {return !isNaN(parseFloat(nOiKiLDCknLYByHnzBJBxoZOrveRyYHpfJZG)) && isFin" ascii
    $s8  = "function hpACMNv(nOiKiLDCknLYByHnzBJBxoZOrveRyYHpfJZG) {return !isNaN(parseFloat(nOiKiLDCknLYByHnzBJBxoZOrveRyYHpfJZG)) && isFin" ascii
    $s9  = "function nXvPtHGTbFjVLoSTySwkemEWIsIpqLQNQYDXVUHoFUhAmVVCAhiIQR(KdeQeEgHJVwNP,lcywEpUmiMZXSs){ return PDIPFtp[czQtIRBQ[jrYwV(Kde" ascii
    $s10 = "function nXvPtHGTbFjVLoSTySwkemEWIsIpqLQNQYDXVUHoFUhAmVVCAhiIQR(KdeQeEgHJVwNP,lcywEpUmiMZXSs){ return PDIPFtp[czQtIRBQ[jrYwV(Kde" ascii
    $s11 = "function oJMAvpPXkhW(cHfxlEiq,gFctia){return cHfxlEiq.split(gFctia)}" fullword ascii
    $s12 = "function V(KNGTwaNZdCiE,FWdtInKzVXornb){KNGTwaNZdCiE.push(FWdtInKzVXornb);}function x5(KESSeyXpWVsbRZGU){if(hpACMNv(KESSeyXpWVsb" ascii
    $s13 = "var K=new Array();" fullword ascii
    $s14 = "function jrYwV(fClhDvKMvSB,aYTwQmJptdLoe,URpGwYzb){hhif=parseInt(fClhDvKMvSB,aYTwQmJptdLoe);PgTJS=hhif.toString(URpGwYzb);return" ascii
    $s15 = "function jrYwV(fClhDvKMvSB,aYTwQmJptdLoe,URpGwYzb){hhif=parseInt(fClhDvKMvSB,aYTwQmJptdLoe);PgTJS=hhif.toString(URpGwYzb);return" ascii
    $s16 = "function NPspoMWumIcYkca(XypLZYUXFhsGWzUHN){eval(XypLZYUXFhsGWzUHN)}" fullword ascii
    $s17 = " PgTJS;}function NPspoMWumIcYkca(XypLZYUXFhsGWzUHN,mRvqBQFbYiOQVhJxIiLSrngsBxlGgIyzMq,CcvQFFUFwBnWAVlrSZLJkqzvctAguaJXTGd){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}