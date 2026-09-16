rule TTP_XOR_MULT_DOSStub_c281 {
  strings:
    $key_c281 = { 96 e9 [2] e2 f1 [2] a5 f3 [2] e2 e2 [2] ac ee [2] a0 e4 [2] b7 ef [2] ac a1 [2] 91 }

  condition:
    any of them
}