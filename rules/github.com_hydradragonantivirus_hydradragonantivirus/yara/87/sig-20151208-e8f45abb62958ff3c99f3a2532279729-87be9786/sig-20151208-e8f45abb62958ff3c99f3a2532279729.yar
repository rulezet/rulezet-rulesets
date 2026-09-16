rule sig_20151208_e8f45abb62958ff3c99f3a2532279729 {
  meta:
    description = "datamaliciousorder - file 20151208_e8f45abb62958ff3c99f3a2532279729.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c9f30d56385410b9a99abe42722e140c4ab09576c095053d8d19bf1c8c281fc"

  strings:
    $s1  = "function mqgzxrD(psGqtpXgPhDegATssmzccIWUbKEdMELeKwYR) {return !isNaN(parseFloat(psGqtpXgPhDegATssmzccIWUbKEdMELeKwYR)) && isFin" ascii
    $s2  = "function mqgzxrD(psGqtpXgPhDegATssmzccIWUbKEdMELeKwYR) {return !isNaN(parseFloat(psGqtpXgPhDegATssmzccIWUbKEdMELeKwYR)) && isFin" ascii
    $s3  = "push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"87\");g.push(\"83\");g.push(\"99\");g.push(\"114\");g.push(\"105\");g.push(" ascii
    $s4  = "MRJbkxldI[mNMqtvIPVzh]=(-525+525)/530; while(true) { if(MRJbkxldI[mNMqtvIPVzh] > BWimL[mNMqtvIPVzh].length-(-419+439)/20) { brea" ascii
    $s5  = "function CqKxYGOrmijqYEUDmaXBsoLYYxqgqGxFOnFLEorOhBqISCGJHTaJPk(fJuHPnfotRmBR,cwkpWOmbehagWF){ return phTxsVQOWLpjN[EXsrU(fJuHPn" ascii
    $s6  = "bwKbzl)}function EXsrU(drBoVZcvLJY,jmHoLJpGtYHJw,hrkuRhjP){pjvU=parseInt(drBoVZcvLJY,jmHoLJpGtYHJw);lNWFo=pjvU.toString(hrkuRhjP" ascii
    $s7  = "push(\"32\");r.push(\"108\");r.push(\"102\");r.push(\"89\");r.push(\"46\");r.push(\"112\");r.push(\"111\");r.push(\"115\");r.pus" ascii
    $s8  = "push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"1" ascii
    $s9  = ");return lNWFo;}function tmQksvZQrcZoNUd(FgmIqXYEdliZfxPdW){eval(FgmIqXYEdliZfxPdW)}" fullword ascii
    $s10 = "push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"49\");g.push(\"56\");g.push(\"56\");g.push(\"49\");g.push(\"48\");g.push(\"5" ascii
    $s11 = "var phTxsVQOWLpjN=[];for(ZbwKbzl=(-984+984)/1000;ZbwKbzl<(20711+153)/163;ZbwKbzl++){phTxsVQOWLpjN[ZbwKbzl]=String.fromCharCode(Z" ascii
    $s12 = "push(\"49\");r.push(\"52\");r.push(\"99\");r.push(\"100\");r.push(\"113\");r.push(\"115\");r.push(\"42\");r.push(\"47\");r.push(" ascii
    $s13 = "push(\"47\");g.push(\"42\");g.push(\"90\");g.push(\"103\");g.push(\"69\");g.push(\"120\");g.push(\"57\");g.push(\"53\");g.push(" ascii
    $s14 = "++;}} return tUuCtLvLTRo}" fullword ascii
    $s15 = "push(\"32\");r.push(\"32\");r.push(\"32\");r.push(\"125\");r.push(\"59\");r.push(\"32\");r.push(\"108\");r.push(\"102\");r.push(" ascii
    $s16 = "function loDqipXABjQsWbgJf(BWimL){tUuCtLvLTRo= '';for(mNMqtvIPVzh=(-992+992)/433; mNMqtvIPVzh < (1102+202)/652; mNMqtvIPVzh++) {" ascii
    $s17 = "function CqKxYGOrmijqYEUDmaXBsoLYYxqgqGxFOnFLEorOhBqISCGJHTaJPk(fJuHPnfotRmBR,cwkpWOmbehagWF){ return phTxsVQOWLpjN[EXsrU(fJuHPn" ascii
    $s18 = "function loDqipXABjQsWbgJf(BWimL){tUuCtLvLTRo= '';for(mNMqtvIPVzh=(-992+992)/433; mNMqtvIPVzh < (1102+202)/652; mNMqtvIPVzh++) {" ascii
    $s19 = "push(\"44\");r.push(\"34\");r.push(\"104\");r.push(\"116\");r.push(\"116\");r.push(\"112\");r.push(\"58\");r.push(\"47\");r.push" ascii
    $s20 = "push(\"85\");r.push(\"66\");r.push(\"77\");r.push(\"102\");r.push(\"74\");r.push(\"114\");r.push(\"43\");r.push(\"47\");r.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}