rule TTP_XOR_MULT_DOSStub_42a2 {
  strings:
    $key_42a2 = { 16 ca [2] 62 d2 [2] 25 d0 [2] 62 c1 [2] 2c cd [2] 20 c7 [2] 37 cc [2] 2c 82 [2] 11 }

  condition:
    any of them
}