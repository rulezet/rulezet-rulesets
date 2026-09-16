rule TTP_XOR_MULT_DOSStub_a42d {
  strings:
    $key_a42d = { f0 45 [2] 84 5d [2] c3 5f [2] 84 4e [2] ca 42 [2] c6 48 [2] d1 43 [2] ca 0d [2] f7 }

  condition:
    any of them
}