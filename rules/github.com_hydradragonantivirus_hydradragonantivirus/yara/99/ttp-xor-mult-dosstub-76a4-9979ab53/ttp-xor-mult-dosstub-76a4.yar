rule TTP_XOR_MULT_DOSStub_76a4 {
  strings:
    $key_76a4 = { 22 cc [2] 56 d4 [2] 11 d6 [2] 56 c7 [2] 18 cb [2] 14 c1 [2] 03 ca [2] 18 84 [2] 25 }

  condition:
    any of them
}