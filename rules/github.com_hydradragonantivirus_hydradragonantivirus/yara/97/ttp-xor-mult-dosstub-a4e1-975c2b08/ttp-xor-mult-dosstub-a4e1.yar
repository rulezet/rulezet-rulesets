rule TTP_XOR_MULT_DOSStub_a4e1 {
  strings:
    $key_a4e1 = { f0 89 [2] 84 91 [2] c3 93 [2] 84 82 [2] ca 8e [2] c6 84 [2] d1 8f [2] ca c1 [2] f7 }

  condition:
    any of them
}