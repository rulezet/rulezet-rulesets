rule TTP_XOR_MULT_DOSStub_64a4 {
  strings:
    $key_64a4 = { 30 cc [2] 44 d4 [2] 03 d6 [2] 44 c7 [2] 0a cb [2] 06 c1 [2] 11 ca [2] 0a 84 [2] 37 }

  condition:
    any of them
}