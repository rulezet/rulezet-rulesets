rule TTP_XOR_MULT_DOSStub_e0a4 {
  strings:
    $key_e0a4 = { b4 cc [2] c0 d4 [2] 87 d6 [2] c0 c7 [2] 8e cb [2] 82 c1 [2] 95 ca [2] 8e 84 [2] b3 }

  condition:
    any of them
}