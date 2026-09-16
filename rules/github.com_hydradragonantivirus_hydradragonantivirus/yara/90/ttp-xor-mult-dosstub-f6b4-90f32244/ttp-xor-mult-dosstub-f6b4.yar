rule TTP_XOR_MULT_DOSStub_f6b4 {
  strings:
    $key_f6b4 = { a2 dc [2] d6 c4 [2] 91 c6 [2] d6 d7 [2] 98 db [2] 94 d1 [2] 83 da [2] 98 94 [2] a5 }

  condition:
    any of them
}