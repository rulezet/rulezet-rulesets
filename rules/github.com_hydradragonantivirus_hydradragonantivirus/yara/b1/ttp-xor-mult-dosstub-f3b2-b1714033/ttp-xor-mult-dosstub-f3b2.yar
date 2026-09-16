rule TTP_XOR_MULT_DOSStub_f3b2 {
  strings:
    $key_f3b2 = { a7 da [2] d3 c2 [2] 94 c0 [2] d3 d1 [2] 9d dd [2] 91 d7 [2] 86 dc [2] 9d 92 [2] a0 }

  condition:
    any of them
}