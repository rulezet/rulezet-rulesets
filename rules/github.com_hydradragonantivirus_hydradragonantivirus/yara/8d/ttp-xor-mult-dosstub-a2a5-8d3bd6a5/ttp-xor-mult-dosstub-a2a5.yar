rule TTP_XOR_MULT_DOSStub_a2a5 {
  strings:
    $key_a2a5 = { f6 cd [2] 82 d5 [2] c5 d7 [2] 82 c6 [2] cc ca [2] c0 c0 [2] d7 cb [2] cc 85 [2] f1 }

  condition:
    any of them
}