rule TTP_XOR_MULT_DOSStub_f1f1 {
  strings:
    $key_f1f1 = { a5 99 [2] d1 81 [2] 96 83 [2] d1 92 [2] 9f 9e [2] 93 94 [2] 84 9f [2] 9f d1 [2] a2 }

  condition:
    any of them
}