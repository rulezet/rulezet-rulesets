rule sig_20151208_ab7f55f62391c184bf4fe5c21ac16362 {
  meta:
    description = "datamaliciousorder - file 20151208_ab7f55f62391c184bf4fe5c21ac16362.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d71535a2a418bfa476877f4bf1b815f392aaa82c65fc432bda7f42c1a8ba7518"

  strings:
    $s1  = "function RgJtmsa(IBCbwiOTEzUISOBpKdyCEzuyzihuiTtOkHMW) {return !isNaN(parseFloat(IBCbwiOTEzUISOBpKdyCEzuyzihuiTtOkHMW)) && isFin" ascii
    $s2  = "function RgJtmsa(IBCbwiOTEzUISOBpKdyCEzuyzihuiTtOkHMW) {return !isNaN(parseFloat(IBCbwiOTEzUISOBpKdyCEzuyzihuiTtOkHMW)) && isFin" ascii
    $s3  = "push(\"47\");x.push(\"82\");x.push(\"117\");x.push(\"110\");x.push(\"40\");x.push(\"87\");x.push(\"79\");x.push(\"119\");x.push(" ascii
    $s4  = "aJLDYmwi[crcnmfffNfT]=(-819+819)/579; while(true) { if(raJLDYmwi[crcnmfffNfT] > eyJch[crcnmfffNfT].length-(-466+755)/289) { brea" ascii
    $s5  = "push(\"87\");x.push(\"70\");x.push(\"119\");x.push(\"46\");x.push(\"115\");x.push(\"97\");x.push(\"118\");x.push(\"101\");x.push" ascii
    $s6  = "function IcpIYRjVGnOGsROld(eyJch){MJZlMIAOwFC= '';for(crcnmfffNfT=(-619+619)/988; crcnmfffNfT < (831+825)/828; crcnmfffNfT++) {r" ascii
    $s7  = ";return fmFLJ;}function sEBtkvduwpCcNmu(sklbBQbAIdsBAhhMS){eval(sklbBQbAIdsBAhhMS)}" fullword ascii
    $s8  = "function IcpIYRjVGnOGsROld(eyJch){MJZlMIAOwFC= '';for(crcnmfffNfT=(-619+619)/988; crcnmfffNfT < (831+825)/828; crcnmfffNfT++) {r" ascii
    $s9  = "var NrKPKmtEnViuF=[];for(NJdZacj=(-881+881)/195;NJdZacj<(114923+21)/898;NJdZacj++){NrKPKmtEnViuF[NJdZacj]=String.fromCharCode(NJ" ascii
    $s10 = "function vZEEztLNKahURpHJcBNheSdSzLLcnJnKboisqlRHizadFoiErdwAGL(FwLdOdivHojPF,fqDyimocscuMfI){ return NrKPKmtEnViuF[cCFGH(FwLdOd" ascii
    $s11 = "push(\"32\");x.push(\"87\");x.push(\"70\");x.push(\"119\");x.push(\"46\");x.push(\"112\");x.push(\"111\");x.push(\"115\");x.push" ascii
    $s12 = "push(\"114\");o.push(\"101\");o.push(\"97\");o.push(\"109\");o.push(\"34\");o.push(\"41\");o.push(\"41\");o.push(\"59\");o.push(" ascii
    $s13 = "++;}} return MJZlMIAOwFC}" fullword ascii
    $s14 = "push(\"32\");x.push(\"61\");x.push(\"32\");x.push(\"48\");x.push(\"59\");x.push(\"13\");x.push(\"10\");x.push(\"32\");x.push(\"3" ascii
    $s15 = "push(\"13\");x.push(\"10\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"125\");x.push(\"59\");x.push(\"" ascii
    $s16 = "function vZEEztLNKahURpHJcBNheSdSzLLcnJnKboisqlRHizadFoiErdwAGL(FwLdOdivHojPF,fqDyimocscuMfI){ return NrKPKmtEnViuF[cCFGH(FwLdOd" ascii
    $s17 = "dZacj)}function cCFGH(iqJWAHuuxCv,UGEYceUlastFy,GZsJpehC){BXkj=parseInt(iqJWAHuuxCv,UGEYceUlastFy);fmFLJ=BXkj.toString(GZsJpehC)" ascii
    $s18 = "function NCyaglCCuVO(TsSRzcaD,BksvYP){return TsSRzcaD.split(BksvYP)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}