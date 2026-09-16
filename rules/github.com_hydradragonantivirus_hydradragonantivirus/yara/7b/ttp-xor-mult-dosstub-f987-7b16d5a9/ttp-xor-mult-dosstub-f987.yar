rule TTP_XOR_MULT_DOSStub_f987 {
  strings:
    $key_f987 = { ad ef [2] d9 f7 [2] 9e f5 [2] d9 e4 [2] 97 e8 [2] 9b e2 [2] 8c e9 [2] 97 a7 [2] aa }

  condition:
    any of them
}