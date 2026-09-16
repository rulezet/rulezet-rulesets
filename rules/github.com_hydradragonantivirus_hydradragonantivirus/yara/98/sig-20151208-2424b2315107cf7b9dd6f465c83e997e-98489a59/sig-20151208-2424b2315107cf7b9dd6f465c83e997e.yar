rule sig_20151208_2424b2315107cf7b9dd6f465c83e997e {
  meta:
    description = "datamaliciousorder - file 20151208_2424b2315107cf7b9dd6f465c83e997e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10b3bb7a008098f06ee9a8a936a99452b2bcb7709268627ef6613b66fdf6ca27"

  strings:
    $s1  = "function PgIVRDs(qqnZWOSeodYrgWdOVhEEVSEsWagZizIoRhog) {return !isNaN(parseFloat(qqnZWOSeodYrgWdOVhEEVSEsWagZizIoRhog)) && isFin" ascii
    $s2  = "function NMXJqByHsQRTsjBpWprnIKBjMtmPCjIxVmdTmaTdKnrNiPEukOLqAt(VyIorJbVTAyTc,UxvCycIxkZJYwE){ return fmzDEkVQLRHKI[EZZRc(VyIorJ" ascii
    $s3  = "function PgIVRDs(qqnZWOSeodYrgWdOVhEEVSEsWagZizIoRhog) {return !isNaN(parseFloat(qqnZWOSeodYrgWdOVhEEVSEsWagZizIoRhog)) && isFin" ascii
    $s4  = "function NMXJqByHsQRTsjBpWprnIKBjMtmPCjIxVmdTmaTdKnrNiPEukOLqAt(VyIorJbVTAyTc,UxvCycIxkZJYwE){ return fmzDEkVQLRHKI[EZZRc(VyIorJ" ascii
    $s5  = "function FIYYqSasgREAsfnnH(nvwed){hNkCPhRIOin= '';for(oDHnPmetoVs=(-83+83)/577; oDHnPmetoVs < (339+85)/212; oDHnPmetoVs++) {aupM" ascii
    $s6  = "push(\"10\");e.push(\"118\");e.push(\"97\");e.push(\"114\");e.push(\"32\");e.push(\"109\");e.push(\"98\");e.push(\"108\");e.push" ascii
    $s7  = "push(\"102\");e.push(\"32\");e.push(\"61\");e.push(\"32\");e.push(\"34\");e.push(\"65\");e.push(\"68\");e.push(\"79\");e.push(\"" ascii
    $s8  = "push(\"87\");e.push(\"83\");e.push(\"99\");e.push(\"114\");e.push(\"105\");e.push(\"34\");e.push(\"58\");e.push(\"34\");e.push(" ascii
    $s9  = "QfqtH)}function EZZRc(hOEvRrwUzZG,EPfEPzfhrbdVW,qSBWwFLz){OFDv=parseInt(hOEvRrwUzZG,EPfEPzfhrbdVW);ozVQQ=OFDv.toString(qSBWwFLz)" ascii
    $s10 = "push(\"10\");g.push(\"9\");g.push(\"9\");g.push(\"125\");g.push(\"59\");g.push(\"32\");g.push(\"13\");g.push(\"10\");g.push(\"32" ascii
    $s11 = "push(\"47\");e.push(\"42\");e.push(\"79\");e.push(\"82\");e.push(\"57\");e.push(\"112\");e.push(\"55\");e.push(\"57\");e.push(\"" ascii
    $s12 = "push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"74\");g.push(\"59\");g.push(\"32\");g.push(\"98\");g.push(\"114\");g.push(\"" ascii
    $s13 = "push(\"75\");g.push(\"46\");g.push(\"111\");g.push(\"112\");g.push(\"101\");g.push(\"110\");g.push(\"40\");g.push(\"112\");g.pus" ascii
    $s14 = "push(\"116\");g.push(\"105\");g.push(\"111\");g.push(\"110\");g.push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"48\");g.push" ascii
    $s15 = "var fmzDEkVQLRHKI=[];for(bFQfqtH=(-583+583)/113;bFQfqtH<(70635+789)/558;bFQfqtH++){fmzDEkVQLRHKI[bFQfqtH]=String.fromCharCode(bF" ascii
    $s16 = "push(\"51\");e.push(\"53\");e.push(\"54\");e.push(\"44\");e.push(\"32\");e.push(\"90\");e.push(\"122\");e.push(\"83\");e.push(\"" ascii
    $s17 = "function cdcCRBmkuUo(TVOPKpqb,MYpCBJ){return TVOPKpqb.split(MYpCBJ)}" fullword ascii
    $s18 = "push(\"32\");g.push(\"61\");g.push(\"32\");g.push(\"48\");g.push(\"59\");g.push(\"13\");g.push(\"10\");g.push(\"32\");g.push(\"3" ascii
    $s19 = "INwSI[oDHnPmetoVs]=(-820+820)/229; while(true) { if(aupMINwSI[oDHnPmetoVs] > nvwed[oDHnPmetoVs].length-(197+774)/971) { break; }" ascii
    $s20 = "push(\"32\");g.push(\"13\");g.push(\"10\");g.push(\"32\");g.push(\"32\");g.push(\"32\");g.push(\"32\");g.push(\"125\");g.push(\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}