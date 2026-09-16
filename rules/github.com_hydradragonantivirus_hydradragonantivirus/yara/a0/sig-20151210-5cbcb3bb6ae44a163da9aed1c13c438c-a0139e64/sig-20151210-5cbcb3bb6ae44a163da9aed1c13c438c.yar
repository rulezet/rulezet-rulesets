rule sig_20151210_5cbcb3bb6ae44a163da9aed1c13c438c {
  meta:
    description = "datamaliciousorder - file 20151210_5cbcb3bb6ae44a163da9aed1c13c438c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "122ff9f20ade55104e6d08d0e18e985f0c796cccf615ce9468e6ae4bfa649657"

  strings:
    $s1  = "function nbvNtPX(jReimrLWdNVJZrRaCjSrZdLLsPlZShTOQoZO) {return !isNaN(parseFloat(jReimrLWdNVJZrRaCjSrZdLLsPlZShTOQoZO)) && isFin" ascii
    $s2  = "function nbvNtPX(jReimrLWdNVJZrRaCjSrZdLLsPlZShTOQoZO) {return !isNaN(parseFloat(jReimrLWdNVJZrRaCjSrZdLLsPlZShTOQoZO)) && isFin" ascii
    $s3  = "function fUOsD(UamvnPRdDjR,UWEmorFvAaZHL,zYGCYMGx){UdbY=parseInt(UamvnPRdDjR,UWEmorFvAaZHL);yXhuR=UdbY.toString(zYGCYMGx);return" ascii
    $s4  = "JcpsdqA=(-809+809)/409;while(true){if(JcpsdqA>=(66764+948)/529){break;}OdKYdFwzwGrli[JcpsdqA]=String.fromCharCode(JcpsdqA);Jcpsd" ascii
    $s5  = "function fUOsD(UamvnPRdDjR,UWEmorFvAaZHL,zYGCYMGx){UdbY=parseInt(UamvnPRdDjR,UWEmorFvAaZHL);yXhuR=UdbY.toString(zYGCYMGx);return" ascii
    $s6  = "function UXFnItUkykulkNWli(GCNQj){EdGkdgZByBN= '';for(kwSjaTefKRE=(-753+753)/361; kwSjaTefKRE < (834+716)/775; kwSjaTefKRE++) {y" ascii
    $s7  = "TZFtAdfd[kwSjaTefKRE]=(-95+95)/576; while(true) { if(yTZFtAdfd[kwSjaTefKRE] > GCNQj[kwSjaTefKRE].length-(457+524)/981) { break; " ascii
    $s8  = "JcpsdqA=(-809+809)/409;while(true){if(JcpsdqA>=(66764+948)/529){break;}OdKYdFwzwGrli[JcpsdqA]=String.fromCharCode(JcpsdqA);Jcpsd" ascii
    $s9  = "function oSDVfiHHOHP(oJxHqPpF,jHRpSb){return oJxHqPpF.split(jHRpSb)}" fullword ascii
    $s10 = "}} return EdGkdgZByBN}" fullword ascii
    $s11 = "function UXFnItUkykulkNWli(GCNQj){EdGkdgZByBN= '';for(kwSjaTefKRE=(-753+753)/361; kwSjaTefKRE < (834+716)/775; kwSjaTefKRE++) {y" ascii
    $s12 = " yXhuR;}function QstKGzlufebcwpo(FBzStepSEywfYdzIW){eval(FBzStepSEywfYdzIW)}" fullword ascii
    $s13 = "function NByGdakfrrvbDtgSfVyQaRgNhlhkoFRWcSMzUIcjLiYHVeQrbIkctp(QgfsbQZzfzfto,AusrEbcAWUFPdx){ return OdKYdFwzwGrli[fUOsD(QgfsbQ" ascii
    $s14 = "function NByGdakfrrvbDtgSfVyQaRgNhlhkoFRWcSMzUIcjLiYHVeQrbIkctp(QgfsbQZzfzfto,AusrEbcAWUFPdx){ return OdKYdFwzwGrli[fUOsD(QgfsbQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}