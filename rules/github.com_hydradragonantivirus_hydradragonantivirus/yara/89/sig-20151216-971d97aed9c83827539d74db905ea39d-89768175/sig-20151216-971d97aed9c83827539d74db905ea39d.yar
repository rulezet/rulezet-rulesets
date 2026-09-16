rule sig_20151216_971d97aed9c83827539d74db905ea39d {
  meta:
    description = "datamaliciousorder - file 20151216_971d97aed9c83827539d74db905ea39d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8329347f56ab3cea1ed3155c8716ce3e5f5d200ca30145093fdabda0a27d396"

  strings:
    $s1  = "ath.cos(329), 2) - 1)));} HOEngrjkF[XDWJDvbZjqc]++;}XDWJDvbZjqc++;} return uAmDatfSZPc}" fullword ascii
    $s2  = ") - 1));while(true){if (XDWJDvbZjqc >= (2142+996)/523){break;}HOEngrjkF[XDWJDvbZjqc]=Math.round((Math.pow(Math.sin(29), 2) + Mat" ascii
    $s3  = "function KxciywnVvsghCDwqF(INzyG){uAmDatfSZPc= '';XDWJDvbZjqc=Math.round((Math.pow(Math.sin(566), 2) + Math.pow(Math.cos(566), 2" ascii
    $s4  = "h.pow(Math.cos(29), 2) - 1)); while(true) { if(HOEngrjkF[XDWJDvbZjqc] > INzyG[XDWJDvbZjqc].length-(697+199)/896) { break; } if (" ascii
    $s5  = "function KxciywnVvsghCDwqF(INzyG){uAmDatfSZPc= '';XDWJDvbZjqc=Math.round((Math.pow(Math.sin(566), 2) + Math.pow(Math.cos(566), 2" ascii
    $s6  = "function fZMEpiT(grbSLGpQuWTvZuKYkYkETLlPZSoJaLfeMCTD) {return !OGkZMIXbdSr(kAPbUoBrgNVEmkh(grbSLGpQuWTvZuKYkYkETLlPZSoJaLfeMCTD" ascii
    $s7  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s8  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s9  = "function lKtEHiyAEixgAwiaJaaRvteSrDdnreXttEKZdtiQbqFsJFuLUbgHMF(poDUTsZowfzPf,aRqQsLXCdHVcyE){ return CKTCzWH[niogewKB[ItIqr(poD" ascii
    $s10 = "function OGkZMIXbdSr(iUIYAjcPxwEIBQ) {return isNaN(iUIYAjcPxwEIBQ);}" fullword ascii
    $s11 = "function ItIqr(QNdqQFVnEgt,rougVqqrKQvfd,rPmlLdoP){NFOt=mjuLdSKqqiwKLBtyT(QNdqQFVnEgt,rougVqqrKQvfd);FwvKE=NFOt.toString(rPmlLdo" ascii
    $s12 = "function fZMEpiT(grbSLGpQuWTvZuKYkYkETLlPZSoJaLfeMCTD) {return !OGkZMIXbdSr(kAPbUoBrgNVEmkh(grbSLGpQuWTvZuKYkYkETLlPZSoJaLfeMCTD" ascii
    $s13 = "P);return FwvKE;}" fullword ascii
    $s14 = "function lKtEHiyAEixgAwiaJaaRvteSrDdnreXttEKZdtiQbqFsJFuLUbgHMF(poDUTsZowfzPf,aRqQsLXCdHVcyE){ return CKTCzWH[niogewKB[ItIqr(poD" ascii
    $s15 = "function ItIqr(QNdqQFVnEgt,rougVqqrKQvfd,rPmlLdoP){NFOt=mjuLdSKqqiwKLBtyT(QNdqQFVnEgt,rougVqqrKQvfd);FwvKE=NFOt.toString(rPmlLdo" ascii
    $s16 = "function tZkvxCEaHixTubw(espKfZJjPXKfcpwJK,ixBEqicijmTBAytRNLHxUvHlfJjDLkEqzC,mHKVNZgIPovQdaehSYifKCUbqDIpBDdOqjj){eval(espKfZJj" ascii
    $s17 = "function m(lUmeGNYuZWHcNH,pprcCLmoDJkgw,ZdYVXLcDKic) {lUmeGNYuZWHcNH[pprcCLmoDJkgw]=ZdYVXLcDKic;}" fullword ascii
    $s18 = "function kAPbUoBrgNVEmkh(TsiPUAOIILjVRMgvAjQ) {return parseFloat(TsiPUAOIILjVRMgvAjQ);}" fullword ascii
    $s19 = "function r(KUrlJeZfAKiC,hOSGJsXSYmzKKH){KUrlJeZfAKiC.push(hOSGJsXSYmzKKH);}" fullword ascii
    $s20 = "function tZkvxCEaHixTubw(espKfZJjPXKfcpwJK,ixBEqicijmTBAytRNLHxUvHlfJjDLkEqzC,mHKVNZgIPovQdaehSYifKCUbqDIpBDdOqjj){eval(espKfZJj" ascii

  condition:
    uint16(0) == 0x696e and
    8 of them
}