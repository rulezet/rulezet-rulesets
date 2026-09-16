rule TTP_XOR_MULT_DOSStub_a42b {
  strings:
    $key_a42b = { f0 43 [2] 84 5b [2] c3 59 [2] 84 48 [2] ca 44 [2] c6 4e [2] d1 45 [2] ca 0b [2] f7 }

  condition:
    any of them
}