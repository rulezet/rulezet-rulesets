rule sig_20151209_ffbf706691078a9e61fc73c5bc140041 {
  meta:
    description = "datamaliciousorder - file 20151209_ffbf706691078a9e61fc73c5bc140041.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0a6435445728ecf5abfe3a804a40e018f69051078db0fcbd4be6d69cb10ffbe"

  strings:
    $s1  = "function pKGmuKf(zQjQYlREXFFDHtwJCpmOVtFZWFrUwxTGptvQ) {return !isNaN(parseFloat(zQjQYlREXFFDHtwJCpmOVtFZWFrUwxTGptvQ)) && isFin" ascii
    $s2  = "function pKGmuKf(zQjQYlREXFFDHtwJCpmOVtFZWFrUwxTGptvQ) {return !isNaN(parseFloat(zQjQYlREXFFDHtwJCpmOVtFZWFrUwxTGptvQ)) && isFin" ascii
    $s3  = "function aiYbNnJqYGFregmOtTwoUxcBMMryGpozUxQFylwCXOTPYzZpwzFSHi(cNOyuTsxdigyo,LGYzKvDQnnWBdx){ return tesQQ[uWDWM(cNOyuTsxdigyo[" ascii
    $s4  = "function koqSYokNRzT(eWgqVFdS,SKnuXp){return eWgqVFdS.split(SKnuXp)}" fullword ascii
    $s5  = "function aiYbNnJqYGFregmOtTwoUxcBMMryGpozUxQFylwCXOTPYzZpwzFSHi(cNOyuTsxdigyo,LGYzKvDQnnWBdx){ return tesQQ[uWDWM(cNOyuTsxdigyo[" ascii
    $s6  = "dMLxftW[ugNkhYOEFxW]=(-192+192)/53; while(true) { if(hAdMLxftW[ugNkhYOEFxW] > iCLsG[ugNkhYOEFxW].length-(23+922)/945) { break; }" ascii
    $s7  = "function quKYwPHNmbTDHbijU(iCLsG){vWHcJIFqBzd= '';for(ugNkhYOEFxW=(-245+245)/46; ugNkhYOEFxW < (389+611)/500; ugNkhYOEFxW++) {hA" ascii
    $s8  = "function quKYwPHNmbTDHbijU(iCLsG){vWHcJIFqBzd= '';for(ugNkhYOEFxW=(-245+245)/46; ugNkhYOEFxW < (389+611)/500; ugNkhYOEFxW++) {hA" ascii
    $s9  = "} return vWHcJIFqBzd}" fullword ascii
    $s10 = " RBtWA;}function vOCtLWyUlQhvDhh(rLWLXEaeZJbvxUMeH){eval(rLWLXEaeZJbvxUMeH)}" fullword ascii
    $s11 = "function uWDWM(iacaJGCxpCy,yAkAaAetCHJKd,cLZrBBiA){nJqh=parseInt(iacaJGCxpCy,yAkAaAetCHJKd);RBtWA=nJqh.toString(cLZrBBiA);return" ascii
    $s12 = "function uWDWM(iacaJGCxpCy,yAkAaAetCHJKd,cLZrBBiA){nJqh=parseInt(iacaJGCxpCy,yAkAaAetCHJKd);RBtWA=nJqh.toString(cLZrBBiA);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}