rule sig_20151210_6e1a5e91dda2bf1b5801f621934e51e0 {
  meta:
    description = "datamaliciousorder - file 20151210_6e1a5e91dda2bf1b5801f621934e51e0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d13962b13c0464d2b17e6d997757d31bc0a335aecce983a87a791dcd27a3f5d8"

  strings:
    $s1  = "function uIUezpJ(RDZrJZWAaqzpScMQMDhyfIDNLPnIyaYxFxUp) {return !isNaN(parseFloat(RDZrJZWAaqzpScMQMDhyfIDNLPnIyaYxFxUp)) && isFin" ascii
    $s2  = "function uIUezpJ(RDZrJZWAaqzpScMQMDhyfIDNLPnIyaYxFxUp) {return !isNaN(parseFloat(RDZrJZWAaqzpScMQMDhyfIDNLPnIyaYxFxUp)) && isFin" ascii
    $s3  = "function QjCgp(LRluRaHxDiP,feYJAMYvdFvHX,ISvJJHbe){rmTc=parseInt(LRluRaHxDiP,feYJAMYvdFvHX);wGNJW=rmTc.toString(ISvJJHbe);return" ascii
    $s4  = "function ZlWTADeXwTAizGMle(GaDwr){VKteklxBfpa= '';for(pjvcctIMgnw=(-791+791)/640; pjvcctIMgnw < (881+917)/899; pjvcctIMgnw++) {Q" ascii
    $s5  = " wGNJW;}function gOoYYhRtnVEeWvv(yUmkiOaKbtxfTqhmY){eval(yUmkiOaKbtxfTqhmY)}" fullword ascii
    $s6  = "jjINjsy=(-98+98)/937;while(true){if(jjINjsy>=(88690+14)/693){break;}shEGyVurlACic[jjINjsy]=String.fromCharCode(jjINjsy);jjINjsy+" ascii
    $s7  = "function KcEWRtsskuAKeQuPvcqdmkVsBHOfxasTYxuIsqKzqzQODLZRlJBGWE(WDOCcqhYcDuwX,NfjFtviIEWnLML){ return shEGyVurlACic[QjCgp(WDOCcq" ascii
    $s8  = "function QjCgp(LRluRaHxDiP,feYJAMYvdFvHX,ISvJJHbe){rmTc=parseInt(LRluRaHxDiP,feYJAMYvdFvHX);wGNJW=rmTc.toString(ISvJJHbe);return" ascii
    $s9  = "function KcEWRtsskuAKeQuPvcqdmkVsBHOfxasTYxuIsqKzqzQODLZRlJBGWE(WDOCcqhYcDuwX,NfjFtviIEWnLML){ return shEGyVurlACic[QjCgp(WDOCcq" ascii
    $s10 = "MvOwaUxs[pjvcctIMgnw]=(-353+353)/829; while(true) { if(QMvOwaUxs[pjvcctIMgnw] > GaDwr[pjvcctIMgnw].length-(-559+596)/37) { break" ascii
    $s11 = "function ZlWTADeXwTAizGMle(GaDwr){VKteklxBfpa= '';for(pjvcctIMgnw=(-791+791)/640; pjvcctIMgnw < (881+917)/899; pjvcctIMgnw++) {Q" ascii
    $s12 = "jjINjsy=(-98+98)/937;while(true){if(jjINjsy>=(88690+14)/693){break;}shEGyVurlACic[jjINjsy]=String.fromCharCode(jjINjsy);jjINjsy+" ascii
    $s13 = "function IaDGYugsZHk(PRXFLPZy,UoMDOd){return PRXFLPZy.split(UoMDOd)}" fullword ascii
    $s14 = "+;}} return VKteklxBfpa}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}