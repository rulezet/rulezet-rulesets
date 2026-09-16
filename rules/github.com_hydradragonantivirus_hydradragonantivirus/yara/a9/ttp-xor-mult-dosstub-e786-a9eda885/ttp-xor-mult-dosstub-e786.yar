rule TTP_XOR_MULT_DOSStub_e786 {
  strings:
    $key_e786 = { b3 ee [2] c7 f6 [2] 80 f4 [2] c7 e5 [2] 89 e9 [2] 85 e3 [2] 92 e8 [2] 89 a6 [2] b4 }

  condition:
    any of them
}