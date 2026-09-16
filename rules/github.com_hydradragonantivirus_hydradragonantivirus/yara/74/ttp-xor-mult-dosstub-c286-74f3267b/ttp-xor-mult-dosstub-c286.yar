rule TTP_XOR_MULT_DOSStub_c286 {
  strings:
    $key_c286 = { 96 ee [2] e2 f6 [2] a5 f4 [2] e2 e5 [2] ac e9 [2] a0 e3 [2] b7 e8 [2] ac a6 [2] 91 }

  condition:
    any of them
}