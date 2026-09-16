rule sig_20151208_362f601258f148b2d0f0ee4688787bc4 {
  meta:
    description = "datamaliciousorder - file 20151208_362f601258f148b2d0f0ee4688787bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b555b099a794e5ab81185b9ce1ace76492c36f7eef90c850e2f1df5de7697ea7"

  strings:
    $s1  = "function vCJsQFj(sPQORWkpQZEpwUaPmOeBDJvsfgJPFohBoIfp) {return !isNaN(parseFloat(sPQORWkpQZEpwUaPmOeBDJvsfgJPFohBoIfp)) && isFin" ascii
    $s2  = "push(\"108\");T.push(\"117\");T.push(\"100\");T.push(\"101\");T.push(\"115\");T.push(\"47\");T.push(\"112\");T.push(\"111\");T.p" ascii
    $s3  = "function vCJsQFj(sPQORWkpQZEpwUaPmOeBDJvsfgJPFohBoIfp) {return !isNaN(parseFloat(sPQORWkpQZEpwUaPmOeBDJvsfgJPFohBoIfp)) && isFin" ascii
    $s4  = "var lLeoBPqKXLgRl=[];for(yDYTMOa=(-615+615)/68;yDYTMOa<(62157+307)/488;yDYTMOa++){lLeoBPqKXLgRl[yDYTMOa]=String.fromCharCode(yDY" ascii
    $s5  = "push(\"116\");n.push(\"46\");n.push(\"67\");n.push(\"114\");n.push(\"101\");n.push(\"97\");n.push(\"116\");n.push(\"101\");n.pus" ascii
    $s6  = "function BCEIhCXGzCyDKKAai(wDDHa){NNPZsGwpUkB= '';for(xigGevftDmr=(-95+95)/252; xigGevftDmr < (501+715)/608; xigGevftDmr++) {gNQ" ascii
    $s7  = "push(\"59\");n.push(\"32\");n.push(\"13\");n.push(\"10\");n.push(\"125\");n.push(\"59\");n.push(\"32\");n.push(\"13\");n.push(\"" ascii
    $s8  = "push(\"79\");T.push(\"68\");T.push(\"34\");T.push(\"59\");T.push(\"13\");T.push(\"10\");T.push(\"118\");T.push(\"97\");T.push(\"" ascii
    $s9  = "function LirYFYKHTWGcVMBmPXMypIfmYXPXtSCZTCzqcqVWqychQOJjFRnMgx(WWIWvnYuuUlgw,ccgEVyVPVWxXwb){ return lLeoBPqKXLgRl[qxLuJ(WWIWvn" ascii
    $s10 = "push(\"68\");n.push(\"118\");n.push(\"107\");n.push(\"72\");n.push(\"104\");n.push(\"43\");n.push(\"34\");n.push(\"46\");n.push(" ascii
    $s11 = "function BCEIhCXGzCyDKKAai(wDDHa){NNPZsGwpUkB= '';for(xigGevftDmr=(-95+95)/252; xigGevftDmr < (501+715)/608; xigGevftDmr++) {gNQ" ascii
    $s12 = "return hwROt;}function xRDCPhjYutHWPMb(sWBRKtSCRWVFyfrNO){eval(sWBRKtSCRWVFyfrNO)}" fullword ascii
    $s13 = "TMOa)}function qxLuJ(RuZLrbMrZNa,FubjdlCQWgISC,nWHGBEHK){bMMf=parseInt(RuZLrbMrZNa,FubjdlCQWgISC);hwROt=bMMf.toString(nWHGBEHK);" ascii
    $s14 = "function LYyhPBtZtme(szEPqArZ,HDtlfS){return szEPqArZ.split(HDtlfS)}" fullword ascii
    $s15 = "function LirYFYKHTWGcVMBmPXMypIfmYXPXtSCZTCzqcqVWqychQOJjFRnMgx(WWIWvnYuuUlgw,ccgEVyVPVWxXwb){ return lLeoBPqKXLgRl[qxLuJ(WWIWvn" ascii
    $s16 = "push(\"95\");T.push(\"112\");T.push(\"97\");T.push(\"103\");T.push(\"101\");T.push(\"115\");T.push(\"95\");T.push(\"115\");T.pus" ascii
    $s17 = "QugSOx[xigGevftDmr]=(-347+347)/251; while(true) { if(gNQQugSOx[xigGevftDmr] > wDDHa[xigGevftDmr].length-(229+674)/903) { break; " ascii
    $s18 = "push(\"97\");n.push(\"108\");n.push(\"115\");n.push(\"101\");n.push(\"41\");n.push(\"59\");n.push(\"32\");n.push(\"86\");n.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}