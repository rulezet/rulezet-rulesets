rule TTP_XOR_MULT_DOSStub_b281 {
  strings:
    $key_b281 = { e6 e9 [2] 92 f1 [2] d5 f3 [2] 92 e2 [2] dc ee [2] d0 e4 [2] c7 ef [2] dc a1 [2] e1 }

  condition:
    any of them
}