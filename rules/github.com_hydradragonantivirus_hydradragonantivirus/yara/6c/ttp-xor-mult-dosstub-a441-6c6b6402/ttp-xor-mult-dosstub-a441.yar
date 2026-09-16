rule TTP_XOR_MULT_DOSStub_a441 {
  strings:
    $key_a441 = { f0 29 [2] 84 31 [2] c3 33 [2] 84 22 [2] ca 2e [2] c6 24 [2] d1 2f [2] ca 61 [2] f7 }

  condition:
    any of them
}