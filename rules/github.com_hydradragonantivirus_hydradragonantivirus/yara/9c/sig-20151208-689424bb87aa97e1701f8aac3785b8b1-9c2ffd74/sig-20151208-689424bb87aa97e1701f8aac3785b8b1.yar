rule sig_20151208_689424bb87aa97e1701f8aac3785b8b1 {
  meta:
    description = "datamaliciousorder - file 20151208_689424bb87aa97e1701f8aac3785b8b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a187092ddffd10ed98a5a7e932afeae346ea9bf19fee29b033d4f49eba2754f"

  strings:
    $s1  = "function FeoBatj(wHCOsPuvYIOXlodFvKbqhoxLfqLNqVGxLTRp) {return !isNaN(parseFloat(wHCOsPuvYIOXlodFvKbqhoxLfqLNqVGxLTRp)) && isFin" ascii
    $s2  = "function FeoBatj(wHCOsPuvYIOXlodFvKbqhoxLfqLNqVGxLTRp) {return !isNaN(parseFloat(wHCOsPuvYIOXlodFvKbqhoxLfqLNqVGxLTRp)) && isFin" ascii
    $s3  = "push(\"59\");k.push(\"13\");k.push(\"10\");k.push(\"118\");k.push(\"97\");k.push(\"114\");k.push(\"32\");k.push(\"81\");k.push(" ascii
    $s4  = "push(\"45\");n.push(\"105\");n.push(\"110\");n.push(\"99\");n.push(\"108\");n.push(\"117\");n.push(\"100\");n.push(\"101\");n.pu" ascii
    $s5  = "push(\"9\");k.push(\"125\");k.push(\"13\");k.push(\"10\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"32\");k.push(\"3" ascii
    $s6  = "push(\"110\");n.push(\"118\");n.push(\"105\");n.push(\"114\");n.push(\"111\");n.push(\"110\");n.push(\"109\");n.push(\"101\");n." ascii
    $s7  = "function ietVKEIRqYWucizhrjrHdEnKMNqKnfUswERBCnlLJLCegqJXUxSJrZ(uPaOZqqAmPPQf,JrqLmudsYHYjlh){ return jWGzEuBqAHNaL[UrlEo(uPaOZq" ascii
    $s8  = "push(\"34\");k.push(\"44\");k.push(\"52\");k.push(\"45\");k.push(\"50\");k.push(\"41\");k.push(\"59\");k.push(\"32\");k.push(\"1" ascii
    $s9  = "push(\"40\");k.push(\"49\");k.push(\"57\");k.push(\"51\");k.push(\"55\");k.push(\"53\");k.push(\"50\");k.push(\"44\");k.push(\"3" ascii
    $s10 = "urn knXoJ;}function OUCPubWYeogXQcF(bFBMQszQksUWGUeSk){eval(bFBMQszQksUWGUeSk)}" fullword ascii
    $s11 = "function KghHaqTGuwd(MNlLQkKp,ODrCBs){return MNlLQkKp.split(ODrCBs)}" fullword ascii
    $s12 = "push(\"116\");k.push(\"101\");k.push(\"40\");k.push(\"113\");k.push(\"98\");k.push(\"46\");k.push(\"114\");k.push(\"101\");k.pus" ascii
    $s13 = "push(\"49\");k.push(\"41\");k.push(\"32\");k.push(\"32\");k.push(\"123\");k.push(\"13\");k.push(\"10\");k.push(\"32\");k.push(\"" ascii
    $s14 = "push(\"111\");k.push(\"112\");k.push(\"101\");k.push(\"110\");k.push(\"40\");k.push(\"112\");k.push(\"111\");k.push(\"105\");k.p" ascii
    $s15 = "function hhcGONYEbOeMhNVrw(zfWkm){jBczugCpkCJ= '';for(RBuuKjMcvHF=(-337+337)/1; RBuuKjMcvHF < (-285+603)/159; RBuuKjMcvHF++) {xO" ascii
    $s16 = "} return jBczugCpkCJ}" fullword ascii
    $s17 = "NWcJrqM[RBuuKjMcvHF]=(-960+960)/487; while(true) { if(xONWcJrqM[RBuuKjMcvHF] > zfWkm[RBuuKjMcvHF].length-(325+54)/379) { break; " ascii
    $s18 = "var jWGzEuBqAHNaL=[];for(hxkLect=(-33+33)/48;hxkLect<(11363+285)/91;hxkLect++){jWGzEuBqAHNaL[hxkLect]=String.fromCharCode(hxkLec" ascii
    $s19 = "push(\"10\");k.push(\"102\");k.push(\"111\");k.push(\"114\");k.push(\"32\");k.push(\"40\");k.push(\"118\");k.push(\"97\");k.push" ascii
    $s20 = "t)}function UrlEo(JuWQlFFgFoG,QgHFPXAabyUBF,gdGbyVqn){CJWF=parseInt(JuWQlFFgFoG,QgHFPXAabyUBF);knXoJ=CJWF.toString(gdGbyVqn);ret" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}