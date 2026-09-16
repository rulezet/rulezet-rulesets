rule TTP_XOR_MULT_DOSStub_e4a6 {
  strings:
    $key_e4a6 = { b0 ce [2] c4 d6 [2] 83 d4 [2] c4 c5 [2] 8a c9 [2] 86 c3 [2] 91 c8 [2] 8a 86 [2] b7 }

  condition:
    any of them
}