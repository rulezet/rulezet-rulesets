rule TTP_XOR_MULT_DOSStub_a457 {
  strings:
    $key_a457 = { f0 3f [2] 84 27 [2] c3 25 [2] 84 34 [2] ca 38 [2] c6 32 [2] d1 39 [2] ca 77 [2] f7 }

  condition:
    any of them
}