rule TTP_XOR_MULT_DOSStub_abe2 {
  strings:
    $key_abe2 = { ff 8a [2] 8b 92 [2] cc 90 [2] 8b 81 [2] c5 8d [2] c9 87 [2] de 8c [2] c5 c2 [2] f8 }

  condition:
    any of them
}