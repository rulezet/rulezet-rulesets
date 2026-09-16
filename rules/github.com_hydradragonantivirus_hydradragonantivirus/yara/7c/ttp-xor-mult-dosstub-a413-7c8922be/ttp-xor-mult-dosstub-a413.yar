rule TTP_XOR_MULT_DOSStub_a413 {
  strings:
    $key_a413 = { f0 7b [2] 84 63 [2] c3 61 [2] 84 70 [2] ca 7c [2] c6 76 [2] d1 7d [2] ca 33 [2] f7 }

  condition:
    any of them
}