rule TTP_XOR_MULT_DOSStub_d48b {
  strings:
    $key_d48b = { 80 e3 [2] f4 fb [2] b3 f9 [2] f4 e8 [2] ba e4 [2] b6 ee [2] a1 e5 [2] ba ab [2] 87 }

  condition:
    any of them
}