rule sig_20151208_0b894b7df6aa9899e6b1f655baa983fd {
  meta:
    description = "datamaliciousorder - file 20151208_0b894b7df6aa9899e6b1f655baa983fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdef67c462b6aeacd6a2361ac0e7ca5c9669d16236374f832eac79c93630a8b9"

  strings:
    $s1  = "function witJhSGvYsCUGHYhI(XIpVZ){nEzlpdYMEYE= '';for(kxPKsQyXrLU=(-103+103)/543; kxPKsQyXrLU < (70+774)/422; kxPKsQyXrLU++) {so" ascii
    $s2  = "function witJhSGvYsCUGHYhI(XIpVZ){nEzlpdYMEYE= '';for(kxPKsQyXrLU=(-103+103)/543; kxPKsQyXrLU < (70+774)/422; kxPKsQyXrLU++) {so" ascii
    $s3  = "} return nEzlpdYMEYE}" fullword ascii
    $s4  = "function wEdnbJW(KLPjvRNbuegfnPkMwCZSckeZTrZUhWwXZUoX) {return !isNaN(parseFloat(KLPjvRNbuegfnPkMwCZSckeZTrZUhWwXZUoX)) && isFin" ascii
    $s5  = "function wEdnbJW(KLPjvRNbuegfnPkMwCZSckeZTrZUhWwXZUoX) {return !isNaN(parseFloat(KLPjvRNbuegfnPkMwCZSckeZTrZUhWwXZUoX)) && isFin" ascii
    $s6  = "uSqsDBb[kxPKsQyXrLU]=(-576+576)/70; while(true) { if(souSqsDBb[kxPKsQyXrLU] > XIpVZ[kxPKsQyXrLU].length-(490+164)/654) { break; " ascii
    $s7  = "push(\"69\");n.push(\"109\");n.push(\"102\");n.push(\"87\");n.push(\"110\");n.push(\"82\");n.push(\"74\");n.push(\"43\");n.push(" ascii
    $s8  = "var ALmZEFuHfJgkp=[];for(prkpPIt=(-39+39)/248;prkpPIt<(11078+954)/94;prkpPIt++){ALmZEFuHfJgkp[prkpPIt]=String.fromCharCode(prkpP" ascii
    $s9  = "It)}function WilUe(aOjKkFUTKGv,mODVRXvvYVvTY,GbiTzTEE){bXbJ=parseInt(aOjKkFUTKGv,mODVRXvvYVvTY);YLzem=bXbJ.toString(GbiTzTEE);re" ascii
    $s10 = "push(\"32\");b.push(\"34\");b.push(\"84\");b.push(\"84\");b.push(\"80\");b.push(\"34\");b.push(\"59\");b.push(\"13\");b.push(\"1" ascii
    $s11 = "push(\"13\");n.push(\"10\");n.push(\"9\");n.push(\"105\");n.push(\"102\");n.push(\"32\");n.push(\"40\");n.push(\"115\");n.push(" ascii
    $s12 = "push(\"32\");n.push(\"50\");n.push(\"53\");n.push(\"52\");n.push(\"51\");n.push(\"45\");n.push(\"57\");n.push(\"48\");n.push(\"5" ascii
    $s13 = "push(\"100\");n.push(\"121\");n.push(\"41\");n.push(\"59\");n.push(\"32\");n.push(\"105\");n.push(\"102\");n.push(\"32\");n.push" ascii
    $s14 = "push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"125\");n.push(\"59\");n.push(\"32\");n.push(\"101\");n.push(" ascii
    $s15 = "push(\"34\");b.push(\"88\");b.push(\"77\");b.push(\"76\");b.push(\"34\");b.push(\"43\");b.push(\"40\");b.push(\"55\");b.push(\"5" ascii
    $s16 = "push(\"105\");n.push(\"102\");n.push(\"32\");n.push(\"40\");n.push(\"40\");n.push(\"40\");n.push(\"110\");n.push(\"101\");n.push" ascii
    $s17 = "function ulZrezJKofhaCRIjHlkvgIkHeQbaCMSPeekXtNuBCPBZiktDkZtuYu(OajpswrnJllYX,qDcZDckycPUSId){ return ALmZEFuHfJgkp[WilUe(Oajpsw" ascii
    $s18 = "push(\"56\");n.push(\"41\");n.push(\"41\");n.push(\"32\");n.push(\"123\");n.push(\"13\");n.push(\"10\");n.push(\"9\");n.push(\"9" ascii
    $s19 = "push(\"13\");n.push(\"10\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"32\");n.push(\"1" ascii
    $s20 = "push(\"106\");b.push(\"32\");b.push(\"61\");b.push(\"32\");b.push(\"34\");b.push(\"65\");b.push(\"68\");b.push(\"79\");b.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}