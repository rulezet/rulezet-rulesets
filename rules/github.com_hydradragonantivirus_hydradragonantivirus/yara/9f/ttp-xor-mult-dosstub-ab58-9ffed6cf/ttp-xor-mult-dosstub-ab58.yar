rule TTP_XOR_MULT_DOSStub_ab58 {
  strings:
    $key_ab58 = { ff 30 [2] 8b 28 [2] cc 2a [2] 8b 3b [2] c5 37 [2] c9 3d [2] de 36 [2] c5 78 [2] f8 }

  condition:
    any of them
}