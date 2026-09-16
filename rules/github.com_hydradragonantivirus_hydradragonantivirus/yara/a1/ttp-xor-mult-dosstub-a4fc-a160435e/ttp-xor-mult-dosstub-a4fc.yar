rule TTP_XOR_MULT_DOSStub_a4fc {
  strings:
    $key_a4fc = { f0 94 [2] 84 8c [2] c3 8e [2] 84 9f [2] ca 93 [2] c6 99 [2] d1 92 [2] ca dc [2] f7 }

  condition:
    any of them
}