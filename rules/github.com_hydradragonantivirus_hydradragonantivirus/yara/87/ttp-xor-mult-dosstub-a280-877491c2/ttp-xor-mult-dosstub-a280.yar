rule TTP_XOR_MULT_DOSStub_a280 {
  strings:
    $key_a280 = { f6 e8 [2] 82 f0 [2] c5 f2 [2] 82 e3 [2] cc ef [2] c0 e5 [2] d7 ee [2] cc a0 [2] f1 }

  condition:
    any of them
}