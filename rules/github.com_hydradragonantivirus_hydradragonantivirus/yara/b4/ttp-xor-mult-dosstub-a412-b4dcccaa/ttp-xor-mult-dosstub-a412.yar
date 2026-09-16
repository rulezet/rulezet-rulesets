rule TTP_XOR_MULT_DOSStub_a412 {
  strings:
    $key_a412 = { f0 7a [2] 84 62 [2] c3 60 [2] 84 71 [2] ca 7d [2] c6 77 [2] d1 7c [2] ca 32 [2] f7 }

  condition:
    any of them
}