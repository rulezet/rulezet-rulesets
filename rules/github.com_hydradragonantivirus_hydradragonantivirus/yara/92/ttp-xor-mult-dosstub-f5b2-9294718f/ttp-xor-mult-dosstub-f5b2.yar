rule TTP_XOR_MULT_DOSStub_f5b2 {
  strings:
    $key_f5b2 = { a1 da [2] d5 c2 [2] 92 c0 [2] d5 d1 [2] 9b dd [2] 97 d7 [2] 80 dc [2] 9b 92 [2] a6 }

  condition:
    any of them
}