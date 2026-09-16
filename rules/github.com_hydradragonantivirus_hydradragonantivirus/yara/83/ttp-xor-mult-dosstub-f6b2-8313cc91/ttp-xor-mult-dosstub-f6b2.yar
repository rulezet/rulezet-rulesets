rule TTP_XOR_MULT_DOSStub_f6b2 {
  strings:
    $key_f6b2 = { a2 da [2] d6 c2 [2] 91 c0 [2] d6 d1 [2] 98 dd [2] 94 d7 [2] 83 dc [2] 98 92 [2] a5 }

  condition:
    any of them
}