rule TTP_XOR_MULT_DOSStub_55a4 {
  strings:
    $key_55a4 = { 01 cc [2] 75 d4 [2] 32 d6 [2] 75 c7 [2] 3b cb [2] 37 c1 [2] 20 ca [2] 3b 84 [2] 06 }

  condition:
    any of them
}