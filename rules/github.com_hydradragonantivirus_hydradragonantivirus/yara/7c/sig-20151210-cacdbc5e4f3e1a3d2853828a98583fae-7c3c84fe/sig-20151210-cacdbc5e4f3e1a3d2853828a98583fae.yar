rule sig_20151210_cacdbc5e4f3e1a3d2853828a98583fae {
  meta:
    description = "datamaliciousorder - file 20151210_cacdbc5e4f3e1a3d2853828a98583fae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef18182d2077b15259f0f1d0db5a1e867ebe609350bdd9b11a71aa1f743aff7"

  strings:
    $s1  = "function yqgFjaH(jDBwopoJbYLNlekaCufBDAFMNVIqsUqIScgj) {return !isNaN(parseFloat(jDBwopoJbYLNlekaCufBDAFMNVIqsUqIScgj)) && isFin" ascii
    $s2  = "function yqgFjaH(jDBwopoJbYLNlekaCufBDAFMNVIqsUqIScgj) {return !isNaN(parseFloat(jDBwopoJbYLNlekaCufBDAFMNVIqsUqIScgj)) && isFin" ascii
    $s3  = "function zNKGvJxVStRQLiYZJ(azPJl){YVmGKDKezus= '';for(ujFlzBSreCy=(-119+119)/949; ujFlzBSreCy < (-826+838)/6; ujFlzBSreCy++) {wq" ascii
    $s4  = "function OJpImknhKqOQKEbUhVaTzPuDvgBPnmueOvImmFiAJgmyiuScwENmtM(zmWthbLmvGsOP,mcQWIrnDssEiGq){ return EaUEgbWMhvufK[EvBtS(zmWthb" ascii
    $s5  = "function OJpImknhKqOQKEbUhVaTzPuDvgBPnmueOvImmFiAJgmyiuScwENmtM(zmWthbLmvGsOP,mcQWIrnDssEiGq){ return EaUEgbWMhvufK[EvBtS(zmWthb" ascii
    $s6  = "function EvBtS(TAiaxtcTunl,NjmDnqDshowhz,oqVYIZcy){EuvG=parseInt(TAiaxtcTunl,NjmDnqDshowhz);IRTgc=EuvG.toString(oqVYIZcy);return" ascii
    $s7  = "WMdcggv=(-465+465)/245;while(true){if(WMdcggv>=(27790+626)/222){break;}EaUEgbWMhvufK[WMdcggv]=String.fromCharCode(WMdcggv);WMdcg" ascii
    $s8  = "DWvBmdA[ujFlzBSreCy]=(-168+168)/864; while(true) { if(wqDWvBmdA[ujFlzBSreCy] > azPJl[ujFlzBSreCy].length-(579+290)/869) { break;" ascii
    $s9  = "function zNKGvJxVStRQLiYZJ(azPJl){YVmGKDKezus= '';for(ujFlzBSreCy=(-119+119)/949; ujFlzBSreCy < (-826+838)/6; ujFlzBSreCy++) {wq" ascii
    $s10 = "} return YVmGKDKezus}" fullword ascii
    $s11 = " IRTgc;}function qSDClgvkYKskPqi(tFTjGyeVxuDAIRnAs){eval(tFTjGyeVxuDAIRnAs)}" fullword ascii
    $s12 = "WMdcggv=(-465+465)/245;while(true){if(WMdcggv>=(27790+626)/222){break;}EaUEgbWMhvufK[WMdcggv]=String.fromCharCode(WMdcggv);WMdcg" ascii
    $s13 = "function lTAaZQYdHNF(shVtAfkM,jQGhwx){return shVtAfkM.split(jQGhwx)}" fullword ascii
    $s14 = "function EvBtS(TAiaxtcTunl,NjmDnqDshowhz,oqVYIZcy){EuvG=parseInt(TAiaxtcTunl,NjmDnqDshowhz);IRTgc=EuvG.toString(oqVYIZcy);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}