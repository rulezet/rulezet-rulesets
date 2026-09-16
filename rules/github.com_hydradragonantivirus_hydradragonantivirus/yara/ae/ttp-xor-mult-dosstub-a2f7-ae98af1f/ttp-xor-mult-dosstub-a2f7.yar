rule TTP_XOR_MULT_DOSStub_a2f7 {
  strings:
    $key_a2f7 = { f6 9f [2] 82 87 [2] c5 85 [2] 82 94 [2] cc 98 [2] c0 92 [2] d7 99 [2] cc d7 [2] f1 }

  condition:
    any of them
}