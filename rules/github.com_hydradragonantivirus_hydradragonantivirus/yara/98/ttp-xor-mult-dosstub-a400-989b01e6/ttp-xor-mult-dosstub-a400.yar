rule TTP_XOR_MULT_DOSStub_a400 {
  strings:
    $key_a400 = { f0 68 [2] 84 70 [2] c3 72 [2] 84 63 [2] ca 6f [2] c6 65 [2] d1 6e [2] ca 20 [2] f7 }

  condition:
    any of them
}