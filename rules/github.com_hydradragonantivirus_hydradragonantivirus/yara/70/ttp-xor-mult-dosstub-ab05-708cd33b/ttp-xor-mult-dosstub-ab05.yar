rule TTP_XOR_MULT_DOSStub_ab05 {
  strings:
    $key_ab05 = { ff 6d [2] 8b 75 [2] cc 77 [2] 8b 66 [2] c5 6a [2] c9 60 [2] de 6b [2] c5 25 [2] f8 }

  condition:
    any of them
}