rule TTP_XOR_MULT_DOSStub_a230 {
  strings:
    $key_a230 = { f6 58 [2] 82 40 [2] c5 42 [2] 82 53 [2] cc 5f [2] c0 55 [2] d7 5e [2] cc 10 [2] f1 }

  condition:
    any of them
}