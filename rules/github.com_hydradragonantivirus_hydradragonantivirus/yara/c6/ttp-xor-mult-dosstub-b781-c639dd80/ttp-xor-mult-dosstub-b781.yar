rule TTP_XOR_MULT_DOSStub_b781 {
  strings:
    $key_b781 = { e3 e9 [2] 97 f1 [2] d0 f3 [2] 97 e2 [2] d9 ee [2] d5 e4 [2] c2 ef [2] d9 a1 [2] e4 }

  condition:
    any of them
}