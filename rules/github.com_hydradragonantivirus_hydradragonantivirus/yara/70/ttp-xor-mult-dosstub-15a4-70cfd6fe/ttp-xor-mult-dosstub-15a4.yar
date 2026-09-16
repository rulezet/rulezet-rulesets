rule TTP_XOR_MULT_DOSStub_15a4 {
  strings:
    $key_15a4 = { 41 cc [2] 35 d4 [2] 72 d6 [2] 35 c7 [2] 7b cb [2] 77 c1 [2] 60 ca [2] 7b 84 [2] 46 }

  condition:
    any of them
}