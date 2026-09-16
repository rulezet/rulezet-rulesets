rule TTP_XOR_MULT_DOSStub_a4fa {
  strings:
    $key_a4fa = { f0 92 [2] 84 8a [2] c3 88 [2] 84 99 [2] ca 95 [2] c6 9f [2] d1 94 [2] ca da [2] f7 }

  condition:
    any of them
}