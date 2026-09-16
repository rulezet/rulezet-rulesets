rule TTP_XOR_MULT_DOSStub_c480 {
  strings:
    $key_c480 = { 90 e8 [2] e4 f0 [2] a3 f2 [2] e4 e3 [2] aa ef [2] a6 e5 [2] b1 ee [2] aa a0 [2] 97 }

  condition:
    any of them
}