rule TTP_XOR_MULT_DOSStub_25a4 {
  strings:
    $key_25a4 = { 71 cc [2] 05 d4 [2] 42 d6 [2] 05 c7 [2] 4b cb [2] 47 c1 [2] 50 ca [2] 4b 84 [2] 76 }

  condition:
    any of them
}