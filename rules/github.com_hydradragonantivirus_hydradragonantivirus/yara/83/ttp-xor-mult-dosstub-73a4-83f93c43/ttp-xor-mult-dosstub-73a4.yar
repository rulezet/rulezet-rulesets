rule TTP_XOR_MULT_DOSStub_73a4 {
  strings:
    $key_73a4 = { 27 cc [2] 53 d4 [2] 14 d6 [2] 53 c7 [2] 1d cb [2] 11 c1 [2] 06 ca [2] 1d 84 [2] 20 }

  condition:
    any of them
}