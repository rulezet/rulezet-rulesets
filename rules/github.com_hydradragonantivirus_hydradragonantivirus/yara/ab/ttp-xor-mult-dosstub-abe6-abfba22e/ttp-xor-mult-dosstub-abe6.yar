rule TTP_XOR_MULT_DOSStub_abe6 {
  strings:
    $key_abe6 = { ff 8e [2] 8b 96 [2] cc 94 [2] 8b 85 [2] c5 89 [2] c9 83 [2] de 88 [2] c5 c6 [2] f8 }

  condition:
    any of them
}