rule TTP_XOR_MULT_DOSStub_a41e {
  strings:
    $key_a41e = { f0 76 [2] 84 6e [2] c3 6c [2] 84 7d [2] ca 71 [2] c6 7b [2] d1 70 [2] ca 3e [2] f7 }

  condition:
    any of them
}