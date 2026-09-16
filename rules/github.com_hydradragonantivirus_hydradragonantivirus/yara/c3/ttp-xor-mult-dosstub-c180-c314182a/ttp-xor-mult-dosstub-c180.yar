rule TTP_XOR_MULT_DOSStub_c180 {
  strings:
    $key_c180 = { 95 e8 [2] e1 f0 [2] a6 f2 [2] e1 e3 [2] af ef [2] a3 e5 [2] b4 ee [2] af a0 [2] 92 }

  condition:
    any of them
}