rule TTP_XOR_MULT_DOSStub_a45e {
  strings:
    $key_a45e = { f0 36 [2] 84 2e [2] c3 2c [2] 84 3d [2] ca 31 [2] c6 3b [2] d1 30 [2] ca 7e [2] f7 }

  condition:
    any of them
}