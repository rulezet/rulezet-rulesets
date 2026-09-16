rule TTP_XOR_MULT_DOSStub_f1e6 {
  strings:
    $key_f1e6 = { a5 8e [2] d1 96 [2] 96 94 [2] d1 85 [2] 9f 89 [2] 93 83 [2] 84 88 [2] 9f c6 [2] a2 }

  condition:
    any of them
}