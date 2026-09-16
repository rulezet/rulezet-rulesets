rule TTP_XOR_MULT_DOSStub_f1f0 {
  strings:
    $key_f1f0 = { a5 98 [2] d1 80 [2] 96 82 [2] d1 93 [2] 9f 9f [2] 93 95 [2] 84 9e [2] 9f d0 [2] a2 }

  condition:
    any of them
}