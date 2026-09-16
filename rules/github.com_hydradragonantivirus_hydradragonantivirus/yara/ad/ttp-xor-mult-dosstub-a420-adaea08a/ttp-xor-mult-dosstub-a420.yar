rule TTP_XOR_MULT_DOSStub_a420 {
  strings:
    $key_a420 = { f0 48 [2] 84 50 [2] c3 52 [2] 84 43 [2] ca 4f [2] c6 45 [2] d1 4e [2] ca 00 [2] f7 }

  condition:
    any of them
}