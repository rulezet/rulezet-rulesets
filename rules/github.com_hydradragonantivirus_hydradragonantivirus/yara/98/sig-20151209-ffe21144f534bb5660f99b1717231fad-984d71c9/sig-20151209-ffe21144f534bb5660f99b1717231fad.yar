rule sig_20151209_ffe21144f534bb5660f99b1717231fad {
  meta:
    description = "datamaliciousorder - file 20151209_ffe21144f534bb5660f99b1717231fad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "654d8a4d4e5440496088435a703bb2256dcab4ea6f8fa8deddebaf56c40066fd"

  strings:
    $s1  = "function ZWbEqbc(SDQHPGLYwCQMLdiPzSSzImuTkaTqOPBnCRAZ) {return !isNaN(parseFloat(SDQHPGLYwCQMLdiPzSSzImuTkaTqOPBnCRAZ)) && isFin" ascii
    $s2  = "function ZWbEqbc(SDQHPGLYwCQMLdiPzSSzImuTkaTqOPBnCRAZ) {return !isNaN(parseFloat(SDQHPGLYwCQMLdiPzSSzImuTkaTqOPBnCRAZ)) && isFin" ascii
    $s3  = "wcjdRPMt[buNRWouQTfB]=(-348+348)/283; while(true) { if(ywcjdRPMt[buNRWouQTfB] > oRMQN[buNRWouQTfB].length-(-890+930)/40) { break" ascii
    $s4  = "function RqZFRZaaNFy(TcGSfUtQ,pmReGH){return TcGSfUtQ.split(pmReGH)}" fullword ascii
    $s5  = "function UfAZI(gEDhjwaYraa,rpRSASmeHsuQD,GoIobikW){KmBW=parseInt(gEDhjwaYraa,rpRSASmeHsuQD);SKEGz=KmBW.toString(GoIobikW);return" ascii
    $s6  = "function yeswRBSAEqeNPQfwV(oRMQN){OvlDxJjuKDp= '';for(buNRWouQTfB=(-119+119)/659; buNRWouQTfB < (162+970)/566; buNRWouQTfB++) {y" ascii
    $s7  = "+;}} return OvlDxJjuKDp}" fullword ascii
    $s8  = "function yeswRBSAEqeNPQfwV(oRMQN){OvlDxJjuKDp= '';for(buNRWouQTfB=(-119+119)/659; buNRWouQTfB < (162+970)/566; buNRWouQTfB++) {y" ascii
    $s9  = " SKEGz;}function UtIxxcYBEzCFlmw(TqqFNtGBLwtzwYVBS){eval(TqqFNtGBLwtzwYVBS)}" fullword ascii
    $s10 = "function WwGAdWGCizvJHDbxNDrbyVCbSPlTXFEXwHzYgJdBCnXbyGCuGgQUVF(DMZFMQrKadtcl,XFZZYqFFOLCLGm){ return jfqFV[UfAZI(DMZFMQrKadtcl[" ascii
    $s11 = "function WwGAdWGCizvJHDbxNDrbyVCbSPlTXFEXwHzYgJdBCnXbyGCuGgQUVF(DMZFMQrKadtcl,XFZZYqFFOLCLGm){ return jfqFV[UfAZI(DMZFMQrKadtcl[" ascii
    $s12 = "function UfAZI(gEDhjwaYraa,rpRSASmeHsuQD,GoIobikW){KmBW=parseInt(gEDhjwaYraa,rpRSASmeHsuQD);SKEGz=KmBW.toString(GoIobikW);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}