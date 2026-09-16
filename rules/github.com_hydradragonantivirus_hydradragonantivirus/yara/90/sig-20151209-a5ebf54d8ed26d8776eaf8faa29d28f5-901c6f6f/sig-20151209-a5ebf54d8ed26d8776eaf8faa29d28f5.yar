rule sig_20151209_a5ebf54d8ed26d8776eaf8faa29d28f5 {
  meta:
    description = "datamaliciousorder - file 20151209_a5ebf54d8ed26d8776eaf8faa29d28f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c40bf27ab129297fc402a6bbb344e74838125f8066500219c23f7bc178d1820"

  strings:
    $s1  = "function vYOHTjM(pOoZYuEFyQwckFqZYIcCiOqhbXWjoUQxJUHj) {return !isNaN(parseFloat(pOoZYuEFyQwckFqZYIcCiOqhbXWjoUQxJUHj)) && isFin" ascii
    $s2  = "function vYOHTjM(pOoZYuEFyQwckFqZYIcCiOqhbXWjoUQxJUHj) {return !isNaN(parseFloat(pOoZYuEFyQwckFqZYIcCiOqhbXWjoUQxJUHj)) && isFin" ascii
    $s3  = "function rmiCCoLStyMrQUQJo(qcHfr){zIpOsWmQoQe= '';for(bMfHKdOQgbK=(-96+96)/958; bMfHKdOQgbK < (80+98)/89; bMfHKdOQgbK++) {VkynAK" ascii
    $s4  = "function JkoEI(dXgUChLqZMa,VAEhtoNhYfdnW,qLpfimHu){SEcY=parseInt(dXgUChLqZMa,VAEhtoNhYfdnW);EzmJt=SEcY.toString(qLpfimHu);return" ascii
    $s5  = "function GThoAXnBlAMdTvFglTQabxZWvMWwRAcuwXdtnrpolAJMjzQjiuEdjD(QphUefbwvaPMV,isInaewPXCHjmc){ return bXzZX[JkoEI(QphUefbwvaPMV[" ascii
    $s6  = " EzmJt;}function dHyRFmxlDBqstzG(MemmUNUqjvbBJFuSV){eval(MemmUNUqjvbBJFuSV)}" fullword ascii
    $s7  = "function xSFVxcbXtXU(FgcPIVZN,UlBQFD){return FgcPIVZN.split(UlBQFD)}" fullword ascii
    $s8  = "rpw[bMfHKdOQgbK]=(-278+278)/763; while(true) { if(VkynAKrpw[bMfHKdOQgbK] > qcHfr[bMfHKdOQgbK].length-(-356+567)/211) { break; } " ascii
    $s9  = "function GThoAXnBlAMdTvFglTQabxZWvMWwRAcuwXdtnrpolAJMjzQjiuEdjD(QphUefbwvaPMV,isInaewPXCHjmc){ return bXzZX[JkoEI(QphUefbwvaPMV[" ascii
    $s10 = "return zIpOsWmQoQe}" fullword ascii
    $s11 = "function rmiCCoLStyMrQUQJo(qcHfr){zIpOsWmQoQe= '';for(bMfHKdOQgbK=(-96+96)/958; bMfHKdOQgbK < (80+98)/89; bMfHKdOQgbK++) {VkynAK" ascii
    $s12 = "function JkoEI(dXgUChLqZMa,VAEhtoNhYfdnW,qLpfimHu){SEcY=parseInt(dXgUChLqZMa,VAEhtoNhYfdnW);EzmJt=SEcY.toString(qLpfimHu);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}