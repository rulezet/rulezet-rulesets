rule TTP_XOR_MULT_DOSStub_a4e0 {
  strings:
    $key_a4e0 = { f0 88 [2] 84 90 [2] c3 92 [2] 84 83 [2] ca 8f [2] c6 85 [2] d1 8e [2] ca c0 [2] f7 }

  condition:
    any of them
}