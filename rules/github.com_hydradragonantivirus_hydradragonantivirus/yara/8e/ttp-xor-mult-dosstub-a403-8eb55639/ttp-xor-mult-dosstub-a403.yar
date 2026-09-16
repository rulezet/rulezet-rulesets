rule TTP_XOR_MULT_DOSStub_a403 {
  strings:
    $key_a403 = { f0 6b [2] 84 73 [2] c3 71 [2] 84 60 [2] ca 6c [2] c6 66 [2] d1 6d [2] ca 23 [2] f7 }

  condition:
    any of them
}