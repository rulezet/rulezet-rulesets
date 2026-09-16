rule TTP_XOR_MULT_DOSStub_d480 {
  strings:
    $key_d480 = { 80 e8 [2] f4 f0 [2] b3 f2 [2] f4 e3 [2] ba ef [2] b6 e5 [2] a1 ee [2] ba a0 [2] 87 }

  condition:
    any of them
}