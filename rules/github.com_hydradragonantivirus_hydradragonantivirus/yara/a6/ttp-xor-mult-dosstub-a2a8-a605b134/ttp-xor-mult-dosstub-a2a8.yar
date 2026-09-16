rule TTP_XOR_MULT_DOSStub_a2a8 {
  strings:
    $key_a2a8 = { f6 c0 [2] 82 d8 [2] c5 da [2] 82 cb [2] cc c7 [2] c0 cd [2] d7 c6 [2] cc 88 [2] f1 }

  condition:
    any of them
}