rule TTP_XOR_MULT_DOSStub_e4a4 {
  strings:
    $key_e4a4 = { b0 cc [2] c4 d4 [2] 83 d6 [2] c4 c7 [2] 8a cb [2] 86 c1 [2] 91 ca [2] 8a 84 [2] b7 }

  condition:
    any of them
}