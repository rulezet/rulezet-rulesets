rule sig_20151208_9d0374966c57c1d5595e502d0872cf60 {
  meta:
    description = "datamaliciousorder - file 20151208_9d0374966c57c1d5595e502d0872cf60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03899904615ad63fb4a15639cc2613b74685b875b0bb7dd1245e608c93f15cdd"

  strings:
    $s1  = "function QmEanEzUXoILkqVgP(zlHuQ){kKCXOTWTrJQ= '';for(IVQvXCOMpZw=(-495+495)/546; IVQvXCOMpZw < (1079+853)/966; IVQvXCOMpZw++) {" ascii
    $s2  = "YsEnjRkRE[IVQvXCOMpZw]=(-936+936)/629; while(true) { if(YsEnjRkRE[IVQvXCOMpZw] > zlHuQ[IVQvXCOMpZw].length-(193+50)/243) { break" ascii
    $s3  = "push(\"115\");q.push(\"112\");q.push(\"111\");q.push(\"110\");q.push(\"115\");q.push(\"101\");q.push(\"66\");q.push(\"111\");q.p" ascii
    $s4  = "function dzrbleU(aGCjmNhNdWcLPugfWlyhCsdtajwBNPOMkOhU) {return !isNaN(parseFloat(aGCjmNhNdWcLPugfWlyhCsdtajwBNPOMkOhU)) && isFin" ascii
    $s5  = "function dzrbleU(aGCjmNhNdWcLPugfWlyhCsdtajwBNPOMkOhU) {return !isNaN(parseFloat(aGCjmNhNdWcLPugfWlyhCsdtajwBNPOMkOhU)) && isFin" ascii
    $s6  = "function QmEanEzUXoILkqVgP(zlHuQ){kKCXOTWTrJQ= '';for(IVQvXCOMpZw=(-495+495)/546; IVQvXCOMpZw < (1079+853)/966; IVQvXCOMpZw++) {" ascii
    $s7  = "function uNRgQgQNlqUMZaUaWSGjREidtPCHPTqvniMmpqNPsveMNEiGDVmALJ(JwxRovwkNLrGZ,TGcFuaoWvQVQet){ return CJgXznNBFcnrg[lpTzG(JwxRov" ascii
    $s8  = "push(\"32\");q.push(\"32\");q.push(\"106\");q.push(\"100\");q.push(\"32\");q.push(\"61\");q.push(\"32\");q.push(\"49\");q.push(" ascii
    $s9  = "push(\"10\");q.push(\"9\");q.push(\"9\");q.push(\"125\");q.push(\"13\");q.push(\"10\");q.push(\"32\");q.push(\"32\");q.push(\"32" ascii
    $s10 = "nGCDT)}function lpTzG(tdqLWyObXkV,exyXDoXymqBgM,kirWehOA){vqCV=parseInt(tdqLWyObXkV,exyXDoXymqBgM);MnwXQ=vqCV.toString(kirWehOA)" ascii
    $s11 = "push(\"47\");A.push(\"42\");A.push(\"52\");A.push(\"99\");A.push(\"65\");A.push(\"121\");A.push(\"50\");A.push(\"53\");A.push(\"" ascii
    $s12 = "function ZRxIqywXbcU(tfOeLaQi,IHqQiy){return tfOeLaQi.split(IHqQiy)}" fullword ascii
    $s13 = "push(\"105\");q.push(\"32\");q.push(\"61\");q.push(\"32\");q.push(\"34\");q.push(\"71\");q.push(\"69\");q.push(\"84\");q.push(\"" ascii
    $s14 = " return kKCXOTWTrJQ}" fullword ascii
    $s15 = "push(\"87\");A.push(\"83\");A.push(\"99\");A.push(\"114\");A.push(\"105\");A.push(\"34\");A.push(\"58\");A.push(\"34\");A.push(" ascii
    $s16 = "push(\"99\");q.push(\"108\");q.push(\"111\");q.push(\"115\");q.push(\"101\");q.push(\"40\");q.push(\"41\");q.push(\"59\");q.push" ascii
    $s17 = "push(\"51\");q.push(\"53\");q.push(\"51\");q.push(\"52\");q.push(\"79\");q.push(\"70\");q.push(\"75\");q.push(\"55\");q.push(\"4" ascii
    $s18 = "push(\"34\");A.push(\"59\");A.push(\"13\");A.push(\"10\");A.push(\"118\");A.push(\"97\");A.push(\"114\");A.push(\"32\");A.push(" ascii
    $s19 = "var CJgXznNBFcnrg=[];for(AnnGCDT=(-457+457)/333;AnnGCDT<(85187+573)/670;AnnGCDT++){CJgXznNBFcnrg[AnnGCDT]=String.fromCharCode(An" ascii
    $s20 = "push(\"116\");q.push(\"114\");q.push(\"121\");q.push(\"32\");q.push(\"32\");q.push(\"123\");q.push(\"13\");q.push(\"10\");q.push" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}