rule sig_20151217_2db22bdc06e3c00b710bc91b284b2ae5 {
  meta:
    description = "datamaliciousorder - file 20151217_2db22bdc06e3c00b710bc91b284b2ae5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25e5a3849a870a7f5b7a4d36e4cff56c5fdef9ea50877549876d3e069fa51c67"

  strings:
    $s1  = "pow(Math.cos(822), 2) - 1)));} RPShokPAv[mJjnnflCqQn]++;}mJjnnflCqQn++;} return KSkFuoUOWpI}" fullword ascii
    $s2  = "h.pow(Math.cos(233), 2) - 1)); while(true) { if(RPShokPAv[mJjnnflCqQn] > NoFQG[mJjnnflCqQn].length-(-479+761)/282) { break; } if" ascii
    $s3  = ") - 1));while(true){if (mJjnnflCqQn >= (269+613)/147){break;}RPShokPAv[mJjnnflCqQn]=Math.round((Math.pow(Math.sin(233), 2) + Mat" ascii
    $s4  = "function qHrJXZBKNkLPnWLuJ(NoFQG){KSkFuoUOWpI= '';mJjnnflCqQn=Math.round((Math.pow(Math.sin(808), 2) + Math.pow(Math.cos(808), 2" ascii
    $s5  = "dbcwUanQhgjRALpoQwctREoYWfrIkOQgtYw([NoFQG[mJjnnflCqQn][RPShokPAv[mJjnnflCqQn]]], Math.round((Math.pow(Math.sin(822), 2) + Math." ascii
    $s6  = "function qHrJXZBKNkLPnWLuJ(NoFQG){KSkFuoUOWpI= '';mJjnnflCqQn=Math.round((Math.pow(Math.sin(808), 2) + Math.pow(Math.cos(808), 2" ascii
    $s7  = "function ZJvRCLI(MrglHHVhtvUoVWgNApyhMMJjEtvIbCnTAOGM) {return !rECkzTcQmWn(YFRnyavbVqeOZZB(MrglHHVhtvUoVWgNApyhMMJjEtvIbCnTAOGM" ascii
    $s8  = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s9  = "function eBjvk(mvrePfUWrvF,PWTLiRgEeomHs,hqhTRgkP){PEJS=rhcnoaZjScWJdrkQr(mvrePfUWrvF,PWTLiRgEeomHs);pMKAU=PEJS.toString(hqhTRgk" ascii
    $s10 = "function rhcnoaZjScWJdrkQr(XhXkBWWJcT,IZijWkgfUM) {return parseInt(XhXkBWWJcT,IZijWkgfUM);}" fullword ascii
    $s11 = "function RvXjjPCXeBllMJfttDrdbcwUanQhgjRALpoQwctREoYWfrIkOQgtYw(GFIMGUmxCicJQ,rvmQYNyQUWKmGE){ return IClqdmK[KQNFaMHd[eBjvk(GFI" ascii
    $s12 = "function xIXiaSAHtPlPgVU(rxRUtsEsriYRpMLDK,WTChSBnFFwCWxVpvfJqKZTXyEAMbuUNLEu,ubbYkfdndiLoMXfplkNHJIIQvyjHfadVFFT){eval(rxRUtsEs" ascii
    $s13 = "function n(tClTzYfnXDmJ,XoAERrhjtbrNzC){tClTzYfnXDmJ.push(XoAERrhjtbrNzC);}" fullword ascii
    $s14 = "function N(wpcEoOizKsHljn,MTjfPVYDdnPQW,BFHIvCjXXfv) {wpcEoOizKsHljn[MTjfPVYDdnPQW]=BFHIvCjXXfv;}" fullword ascii
    $s15 = "function RvXjjPCXeBllMJfttDrdbcwUanQhgjRALpoQwctREoYWfrIkOQgtYw(GFIMGUmxCicJQ,rvmQYNyQUWKmGE){ return IClqdmK[KQNFaMHd[eBjvk(GFI" ascii
    $s16 = "P);return pMKAU;}" fullword ascii
    $s17 = "function ZJvRCLI(MrglHHVhtvUoVWgNApyhMMJjEtvIbCnTAOGM) {return !rECkzTcQmWn(YFRnyavbVqeOZZB(MrglHHVhtvUoVWgNApyhMMJjEtvIbCnTAOGM" ascii
    $s18 = "var f = new Array();f[0]=[];f[0][0]='d';f[0][1]='a';f[0][2]='d';f[0][3]='a';f[0][4]='46';f[0][5]='3d';f[0][6]='42';f[0][7]='14';" ascii
    $s19 = "function pBzNpyjLlIOR(rdlfZIrFKQxKl) {return isFinite(rdlfZIrFKQxKl);}" fullword ascii
    $s20 = "function rECkzTcQmWn(NvLSzRILlaiyJS) {return isNaN(NvLSzRILlaiyJS);}" fullword ascii

  condition:
    uint16(0) == 0x514b and
    8 of them
}