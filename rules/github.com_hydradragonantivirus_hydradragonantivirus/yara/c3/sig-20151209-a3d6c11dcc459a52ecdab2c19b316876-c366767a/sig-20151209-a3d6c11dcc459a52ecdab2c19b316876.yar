rule sig_20151209_a3d6c11dcc459a52ecdab2c19b316876 {
  meta:
    description = "datamaliciousorder - file 20151209_a3d6c11dcc459a52ecdab2c19b316876.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0d999ee8fd545a929e9afc3f33732c39f4c9906d3da611d2fb2dd44feb37652"

  strings:
    $s1  = "function iDUWAwn(kjSTUxbWdiBrSZMldBtDkMkROLWnKrnqSKFg) {return !isNaN(parseFloat(kjSTUxbWdiBrSZMldBtDkMkROLWnKrnqSKFg)) && isFin" ascii
    $s2  = "function KhVeLgpjIUA(OcoMpJbS,eSiLGN){return OcoMpJbS.split(eSiLGN)}" fullword ascii
    $s3  = "function iDUWAwn(kjSTUxbWdiBrSZMldBtDkMkROLWnKrnqSKFg) {return !isNaN(parseFloat(kjSTUxbWdiBrSZMldBtDkMkROLWnKrnqSKFg)) && isFin" ascii
    $s4  = "function mCFwZ(vrWOyZAeDhy,HiwYpojCjShfz,kSIwoyhy){uuBg=parseInt(vrWOyZAeDhy,HiwYpojCjShfz);vRoYx=uuBg.toString(kSIwoyhy);return" ascii
    $s5  = "function NvYCsZjxhXzOVHAWYduAXsqCxXqwOoIAWFunSYZampNAcecxZLlOxK(xYmvJodUgSynf,UFffkMCkslhwYy){ return UHpep[mCFwZ(xYmvJodUgSynf[" ascii
    $s6  = "function mCFwZ(vrWOyZAeDhy,HiwYpojCjShfz,kSIwoyhy){uuBg=parseInt(vrWOyZAeDhy,HiwYpojCjShfz);vRoYx=uuBg.toString(kSIwoyhy);return" ascii
    $s7  = " vRoYx;}function MbdVFfytmyrIohG(cvApeWXjAbFYtNhvV){eval(cvApeWXjAbFYtNhvV)}" fullword ascii
    $s8  = "hCFfrvuWk[RQbyhRwFrxT]=(-468+468)/725; while(true) { if(hCFfrvuWk[RQbyhRwFrxT] > xrIUw[RQbyhRwFrxT].length-(-340+808)/468) { bre" ascii
    $s9  = "]++;}} return DSezDTwDljl}" fullword ascii
    $s10 = "function NvYCsZjxhXzOVHAWYduAXsqCxXqwOoIAWFunSYZampNAcecxZLlOxK(xYmvJodUgSynf,UFffkMCkslhwYy){ return UHpep[mCFwZ(xYmvJodUgSynf[" ascii
    $s11 = "function CifHlZZQbBxDANSDy(xrIUw){DSezDTwDljl= '';for(RQbyhRwFrxT=(-117+117)/958; RQbyhRwFrxT < (-135+375)/120; RQbyhRwFrxT++) {" ascii
    $s12 = "function CifHlZZQbBxDANSDy(xrIUw){DSezDTwDljl= '';for(RQbyhRwFrxT=(-117+117)/958; RQbyhRwFrxT < (-135+375)/120; RQbyhRwFrxT++) {" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}