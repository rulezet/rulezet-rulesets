rule TTP_XOR_MULT_DOSStub_a480 {
  strings:
    $key_a480 = { f0 e8 [2] 84 f0 [2] c3 f2 [2] 84 e3 [2] ca ef [2] c6 e5 [2] d1 ee [2] ca a0 [2] f7 }

  condition:
    any of them
}