rule TTP_XOR_MULT_DOSStub_e4b9 {
  strings:
    $key_e4b9 = { b0 d1 [2] c4 c9 [2] 83 cb [2] c4 da [2] 8a d6 [2] 86 dc [2] 91 d7 [2] 8a 99 [2] b7 }

  condition:
    any of them
}