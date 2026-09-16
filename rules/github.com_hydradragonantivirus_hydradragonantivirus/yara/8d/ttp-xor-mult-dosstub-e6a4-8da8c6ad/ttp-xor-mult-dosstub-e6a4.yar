rule TTP_XOR_MULT_DOSStub_e6a4 {
  strings:
    $key_e6a4 = { b2 cc [2] c6 d4 [2] 81 d6 [2] c6 c7 [2] 88 cb [2] 84 c1 [2] 93 ca [2] 88 84 [2] b5 }

  condition:
    any of them
}