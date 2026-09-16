rule TTP_XOR_MULT_DOSStub_b787 {
  strings:
    $key_b787 = { e3 ef [2] 97 f7 [2] d0 f5 [2] 97 e4 [2] d9 e8 [2] d5 e2 [2] c2 e9 [2] d9 a7 [2] e4 }

  condition:
    any of them
}