rule sig_20151210_de80cc6ca045a25ad0d6771f678e6744 {
  meta:
    description = "datamaliciousorder - file 20151210_de80cc6ca045a25ad0d6771f678e6744.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de6b48e12a15e0e8eaeb6c2bb32adfdb0bd983569daff3f9a6807504e8ce2a7d"

  strings:
    $s1  = "function ouctHgC(lZkodFdiBOTsBedKKwsxMlZipLghrSskLJwV) {return !isNaN(parseFloat(lZkodFdiBOTsBedKKwsxMlZipLghrSskLJwV)) && isFin" ascii
    $s2  = "function ouctHgC(lZkodFdiBOTsBedKKwsxMlZipLghrSskLJwV) {return !isNaN(parseFloat(lZkodFdiBOTsBedKKwsxMlZipLghrSskLJwV)) && isFin" ascii
    $s3  = "function HMhoP(aHdRZJaLqwI,ZrxQbMtRjEAsg,jdxiJGuj){ZgeH=parseInt(aHdRZJaLqwI,ZrxQbMtRjEAsg);kXGLR=ZgeH.toString(jdxiJGuj);return" ascii
    $s4  = "GBVFbznp[drtTFdtCTFh]=(-969+969)/856; while(true) { if(cGBVFbznp[drtTFdtCTFh] > PjnuI[drtTFdtCTFh].length-(208+585)/793) { break" ascii
    $s5  = "function rGEivLHIdgb(xbJfXmuO,nalpAY){return xbJfXmuO.split(nalpAY)}" fullword ascii
    $s6  = "function gARfWuuweQxErQhaU(PjnuI){bpJmghgMqoF= '';for(drtTFdtCTFh=(-183+183)/430; drtTFdtCTFh < (1520+60)/790; drtTFdtCTFh++) {c" ascii
    $s7  = "function gARfWuuweQxErQhaU(PjnuI){bpJmghgMqoF= '';for(drtTFdtCTFh=(-183+183)/430; drtTFdtCTFh < (1520+60)/790; drtTFdtCTFh++) {c" ascii
    $s8  = "+;}} return bpJmghgMqoF}" fullword ascii
    $s9  = " kXGLR;}function FfKeGpZeKMRVSYv(qEPuOEexVDEUzDMHG){eval(qEPuOEexVDEUzDMHG)}" fullword ascii
    $s10 = "function HMhoP(aHdRZJaLqwI,ZrxQbMtRjEAsg,jdxiJGuj){ZgeH=parseInt(aHdRZJaLqwI,ZrxQbMtRjEAsg);kXGLR=ZgeH.toString(jdxiJGuj);return" ascii
    $s11 = "function DcSlSwQcEHlFMWxPKxsdQPkTcwypXOKYtqtMrJzSLXjsezWxtGjfJK(yHtcZVHlnsUTP,dgzytvTqkbnIJJ){ return eWwDoCDCAGdmy[HMhoP(yHtcZV" ascii
    $s12 = "function DcSlSwQcEHlFMWxPKxsdQPkTcwypXOKYtqtMrJzSLXjsezWxtGjfJK(yHtcZVHlnsUTP,dgzytvTqkbnIJJ){ return eWwDoCDCAGdmy[HMhoP(yHtcZV" ascii
    $s13 = "nHQdbzm=(-950+950)/296;while(true){if(nHQdbzm>=(109191+761)/859){break;}eWwDoCDCAGdmy[nHQdbzm]=String.fromCharCode(nHQdbzm);nHQd" ascii
    $s14 = "nHQdbzm=(-950+950)/296;while(true){if(nHQdbzm>=(109191+761)/859){break;}eWwDoCDCAGdmy[nHQdbzm]=String.fromCharCode(nHQdbzm);nHQd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}