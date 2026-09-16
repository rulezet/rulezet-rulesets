rule TTP_XOR_MULT_DOSStub_f3b4 {
  strings:
    $key_f3b4 = { a7 dc [2] d3 c4 [2] 94 c6 [2] d3 d7 [2] 9d db [2] 91 d1 [2] 86 da [2] 9d 94 [2] a0 }

  condition:
    any of them
}