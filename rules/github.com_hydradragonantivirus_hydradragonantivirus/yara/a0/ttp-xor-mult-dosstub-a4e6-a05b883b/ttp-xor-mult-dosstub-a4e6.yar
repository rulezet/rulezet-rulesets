rule TTP_XOR_MULT_DOSStub_a4e6 {
  strings:
    $key_a4e6 = { f0 8e [2] 84 96 [2] c3 94 [2] 84 85 [2] ca 89 [2] c6 83 [2] d1 88 [2] ca c6 [2] f7 }

  condition:
    any of them
}