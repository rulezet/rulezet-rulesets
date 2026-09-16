rule TTP_XOR_MULT_DOSStub_f1f7 {
  strings:
    $key_f1f7 = { a5 9f [2] d1 87 [2] 96 85 [2] d1 94 [2] 9f 98 [2] 93 92 [2] 84 99 [2] 9f d7 [2] a2 }

  condition:
    any of them
}