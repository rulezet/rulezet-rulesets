rule TTP_XOR_MULT_DOSStub_ab12 {
  strings:
    $key_ab12 = { ff 7a [2] 8b 62 [2] cc 60 [2] 8b 71 [2] c5 7d [2] c9 77 [2] de 7c [2] c5 32 [2] f8 }

  condition:
    any of them
}