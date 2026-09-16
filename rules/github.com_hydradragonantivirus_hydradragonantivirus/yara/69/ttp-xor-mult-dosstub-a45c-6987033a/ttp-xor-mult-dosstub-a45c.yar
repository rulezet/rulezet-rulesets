rule TTP_XOR_MULT_DOSStub_a45c {
  strings:
    $key_a45c = { f0 34 [2] 84 2c [2] c3 2e [2] 84 3f [2] ca 33 [2] c6 39 [2] d1 32 [2] ca 7c [2] f7 }

  condition:
    any of them
}