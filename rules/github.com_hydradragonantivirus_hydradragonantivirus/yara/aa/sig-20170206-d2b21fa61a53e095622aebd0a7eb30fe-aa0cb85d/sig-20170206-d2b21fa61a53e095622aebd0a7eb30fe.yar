rule sig_20170206_d2b21fa61a53e095622aebd0a7eb30fe {
  meta:
    description = "datamaliciousorder - file 20170206_d2b21fa61a53e095622aebd0a7eb30fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1310adea3cb7cb0fc61622353a7040343a9b6dd6bc1750d182a8fd695f2bd3"

  strings:
    $s1  = "iddifkyhmefenqivlafihduvvuvysryzehexridnyzocgeczaxtorvofycummamebxadydabyqpupyvysleltatabakeqemyddifhybivuwaxpyzelysjomrawiwifgi" ascii
    $s2  = "mxukmuzlywq2[usar[ijsoqu[2]] + jomukxo[fory[1]]](wubyzl[kvevo[3]] + jxiwygi[aggeto[5]] + yqucdy[rydfazd[4]] + ajhotix[xpozjekt[3" ascii
    $s3  = "if ([\"esav820kcewv\", new Function(bybek[fmavcilt[2]] + isuly[trise[2]] + umnonyh[rygli[3]] + aklag[sbifaqb[3]] + ikxoncu[xyxyx" ascii
    $s4  = "hriblidnosaqikxu0[occuq[susxe[2]] + bijfikcu[akcov[3]] + site[opavpi[1]] + ebukmegq[omucr[4]] + uqjadyj[edyqj[0]] + enqetnubx[qy" ascii
    $s5  = "fijilippismuwisroleqiwojzakqigtugnaxaqqavijrokwyrhagibhakciwazaltejegawkaqmussevusvoxmasgarhafkuberzockockajqykagu4 = this[ohaly" ascii
    $s6  = "if ([\"esav820kcewv\", new Function(bybek[fmavcilt[2]] + isuly[trise[2]] + umnonyh[rygli[3]] + aklag[sbifaqb[3]] + ikxoncu[xyxyx" ascii
    $s7  = "dovixulzypsyxnokalajununqepzizipcubefukasibywmocalavywsabdahmygjohosatagebdewhykxolnevwylylgoqvuvutoqpygpyvqomqalobceslorlacuqyq" ascii
    $s8  = "var site = [\"pe\", \"dve895ywe\"];" fullword ascii
    $s9  = "udmactezadifmujufivnuxnozoblylannibjacilligjywwuqtygkoxfifsutfapivupqufifapumydceqbagqamybijokvokguckarysxinpeknaqjorijsypyqamyk" ascii
    $s10 = "var usar = [\"sucpu422qafi\", \"ru\", \"xrahn318owvirm\"];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}