rule TTP_XOR_MULT_DOSStub_f2b2 {
  strings:
    $key_f2b2 = { a6 da [2] d2 c2 [2] 95 c0 [2] d2 d1 [2] 9c dd [2] 90 d7 [2] 87 dc [2] 9c 92 [2] a1 }

  condition:
    any of them
}