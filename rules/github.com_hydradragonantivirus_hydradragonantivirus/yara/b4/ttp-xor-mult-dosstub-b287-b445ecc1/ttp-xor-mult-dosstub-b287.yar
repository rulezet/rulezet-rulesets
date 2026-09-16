rule TTP_XOR_MULT_DOSStub_b287 {
  strings:
    $key_b287 = { e6 ef [2] 92 f7 [2] d5 f5 [2] 92 e4 [2] dc e8 [2] d0 e2 [2] c7 e9 [2] dc a7 [2] e1 }

  condition:
    any of them
}