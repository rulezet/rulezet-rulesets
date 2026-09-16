rule sig_20151217_439b46c22551fd1677a641c05cfa113a {
  meta:
    description = "datamaliciousorder - file 20151217_439b46c22551fd1677a641c05cfa113a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b83796db35995a2c43272b611189d5353d7594972fce4b3942b000ad430e2b93"

  strings:
    $s1  = "function cLeKqBVLsMVcvcYrx(RxgGK){lyekfQjXgff= '';oieVxtyEipe=Math.round((Math.pow(Math.sin(932), 2) + Math.pow(Math.cos(932), 2" ascii
    $s2  = "w(Math.cos(906), 2) - 1)));} nuDBQRham[oieVxtyEipe]++;}oieVxtyEipe++;} return lyekfQjXgff}" fullword ascii
    $s3  = ") - 1));while(true){if (oieVxtyEipe >= (1558+614)/362){break;}nuDBQRham[oieVxtyEipe]=Math.round((Math.pow(Math.sin(473), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(473), 2) - 1)); while(true) { if(nuDBQRham[oieVxtyEipe] > RxgGK[oieVxtyEipe].length-(425+12)/437) { break; } if " ascii
    $s5  = "function cLeKqBVLsMVcvcYrx(RxgGK){lyekfQjXgff= '';oieVxtyEipe=Math.round((Math.pow(Math.sin(932), 2) + Math.pow(Math.cos(932), 2" ascii
    $s6  = "function RrfNyrH(oPpVRQNGiioayfnzrwThxvKYuFliaNxJHxCE) {return !SrQlLtpSthk(BiFryPnyNVpJkRt(oPpVRQNGiioayfnzrwThxvKYuFliaNxJHxCE" ascii
    $s7  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s8  = "function KATmabhajXqHyRGxz(hXigHxotFS,PZLEgkGtbQ) {return parseInt(hXigHxotFS,PZLEgkGtbQ);}" fullword ascii
    $s9  = "function EgwYz(fPbBjjhCuEV,JhTRkTfjrALZN,gLGujaHn){ReHZ=KATmabhajXqHyRGxz(fPbBjjhCuEV,JhTRkTfjrALZN);fkjoD=ReHZ.toString(gLGujaH" ascii
    $s10 = "function EgwYz(fPbBjjhCuEV,JhTRkTfjrALZN,gLGujaHn){ReHZ=KATmabhajXqHyRGxz(fPbBjjhCuEV,JhTRkTfjrALZN);fkjoD=ReHZ.toString(gLGujaH" ascii
    $s11 = "function heSZrSWzYlFurGj(MRPtxfdeJbbBaqMfo,EypzIoyBxiIklfeEMGDlTKZulBrlAtFRbt,HtLpyRbPUPZCxKopfNFWxgHYizPSeMFnpeT){eval(MRPtxfde" ascii
    $s12 = "function RrfNyrH(oPpVRQNGiioayfnzrwThxvKYuFliaNxJHxCE) {return !SrQlLtpSthk(BiFryPnyNVpJkRt(oPpVRQNGiioayfnzrwThxvKYuFliaNxJHxCE" ascii
    $s13 = "function f(njEtEFxWWMVb,xOobBBzfsrbAjB){njEtEFxWWMVb.push(xOobBBzfsrbAjB);}" fullword ascii
    $s14 = "function h(iazBxTHNmbAbTg,dlkPtbcYdsMnM,kRyfLqLoKjC) {iazBxTHNmbAbTg[dlkPtbcYdsMnM]=kRyfLqLoKjC;}" fullword ascii
    $s15 = "function wiwaKYPkSvfzueVlifTsyxhReMkdwTKHWHWslzBopbNpVtDfINVLUx(vUGKXKNnGXRxy,rTZjZdxiBnHNdh){ return WajRAqv[nhIVpZKa[EgwYz(vUG" ascii
    $s16 = "function sROpIWuBagxQ(GiplRuibAZiKC) {return isFinite(GiplRuibAZiKC);}" fullword ascii
    $s17 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s18 = "function heSZrSWzYlFurGj(MRPtxfdeJbbBaqMfo,EypzIoyBxiIklfeEMGDlTKZulBrlAtFRbt,HtLpyRbPUPZCxKopfNFWxgHYizPSeMFnpeT){eval(MRPtxfde" ascii
    $s19 = "function wiwaKYPkSvfzueVlifTsyxhReMkdwTKHWHWslzBopbNpVtDfINVLUx(vUGKXKNnGXRxy,rTZjZdxiBnHNdh){ return WajRAqv[nhIVpZKa[EgwYz(vUG" ascii
    $s20 = "n);return fkjoD;}" fullword ascii

  condition:
    uint16(0) == 0x686e and
    8 of them
}