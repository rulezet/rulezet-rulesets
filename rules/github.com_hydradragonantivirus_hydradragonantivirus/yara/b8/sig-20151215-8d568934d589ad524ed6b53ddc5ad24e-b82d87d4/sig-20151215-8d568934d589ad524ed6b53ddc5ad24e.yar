rule sig_20151215_8d568934d589ad524ed6b53ddc5ad24e {
  meta:
    description = "datamaliciousorder - file 20151215_8d568934d589ad524ed6b53ddc5ad24e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ee6029ea8a198eb02ff0e364ca70a57ec46d56e2004252325545bd06ae3f5a2"

  strings:
    $s1  = "Math.pow(Math.cos(687), 2) - 1)); while(true) { if(NYJYlrour[ODfdbPlyiVJ] > cGaqa[ODfdbPlyiVJ].length-(442+197)/639) { break; } " ascii
    $s2  = "function YknWlnzOwdzArVSmt(cGaqa){MPEvIZBMPnF= k[1831];for(ODfdbPlyiVJ=Math.round((Math.pow(Math.sin(283), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(335), 2) - 1)));} NYJYlrour[ODfdbPlyiVJ]++;}} return MPEvIZBMPnF}" fullword ascii
    $s4  = "function YknWlnzOwdzArVSmt(cGaqa){MPEvIZBMPnF= k[1831];for(ODfdbPlyiVJ=Math.round((Math.pow(Math.sin(283), 2) + Math.pow(Math.co" ascii
    $s5  = "function d(PUmxJmCgThRJ,IeKqWFIpnShbHU){PUmxJmCgThRJ.push(IeKqWFIpnShbHU);}function f5(YNwbIhnszRLdabLO){if(bvFEzfs(YNwbIhnszRLd" ascii
    $s6  = "abLO)) {return (String.fromCharCode(YNwbIhnszRLdabLO) + String.fromCharCode((53702+730)/648));}}" fullword ascii
    $s7  = "function bvFEzfs(WeUenaZXoUOuFmugTbtFgqGBpiInYHhNnLhw) {return !isNaN(parseFloat(WeUenaZXoUOuFmugTbtFgqGBpiInYHhNnLhw)) && isFin" ascii
    $s8  = "function bvFEzfs(WeUenaZXoUOuFmugTbtFgqGBpiInYHhNnLhw) {return !isNaN(parseFloat(WeUenaZXoUOuFmugTbtFgqGBpiInYHhNnLhw)) && isFin" ascii
    $s9  = "function hqqRJ(IgpVbkUtQdv,wKBMQiGhDyAtA,AHkzGyan){EIjK=parseInt(IgpVbkUtQdv,wKBMQiGhDyAtA);hRTff=EIjK.toString(AHkzGyan);return" ascii
    $s10 = "function aQXDHjZUfOTStGFVadtxxsmriLBahCmbjmkPOneNQpHiEholdDgBLn(LuLalcCbsgBbl,rbTSGTgFvEKBmL){ return Dbxaedn[vSgpunNL[hqqRJ(LuL" ascii
    $s11 = "function qVhFuqrKiboxoQT(srzPrxyaSRwDgrSSF){eval(srzPrxyaSRwDgrSSF)}" fullword ascii
    $s12 = "function aQXDHjZUfOTStGFVadtxxsmriLBahCmbjmkPOneNQpHiEholdDgBLn(LuLalcCbsgBbl,rbTSGTgFvEKBmL){ return Dbxaedn[vSgpunNL[hqqRJ(LuL" ascii
    $s13 = "var k=new Array();" fullword ascii
    $s14 = " hRTff;}function qVhFuqrKiboxoQT(srzPrxyaSRwDgrSSF,RYBMWyEZJVGDFxWdQIDwuRNuHUEvMgzCox,VREIfLPXOHeRHLyTagOdIVjAyZAMPzyBZlA){eval(" ascii
    $s15 = "function hqqRJ(IgpVbkUtQdv,wKBMQiGhDyAtA,AHkzGyan){EIjK=parseInt(IgpVbkUtQdv,wKBMQiGhDyAtA);hRTff=EIjK.toString(AHkzGyan);return" ascii
    $s16 = "function YnTOKzzSngh(XucojwLd,vTXdnm){return XucojwLd.split(vTXdnm)}" fullword ascii
    $s17 = "function d(PUmxJmCgThRJ,IeKqWFIpnShbHU){PUmxJmCgThRJ.push(IeKqWFIpnShbHU);}function f5(YNwbIhnszRLdabLO){if(bvFEzfs(YNwbIhnszRLd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}