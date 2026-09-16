rule TTP_XOR_MULT_DOSStub_a430 {
  strings:
    $key_a430 = { f0 58 [2] 84 40 [2] c3 42 [2] 84 53 [2] ca 5f [2] c6 55 [2] d1 5e [2] ca 10 [2] f7 }

  condition:
    any of them
}