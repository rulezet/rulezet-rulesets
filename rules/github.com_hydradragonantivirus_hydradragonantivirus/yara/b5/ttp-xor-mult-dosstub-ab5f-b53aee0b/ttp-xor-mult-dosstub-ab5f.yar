rule TTP_XOR_MULT_DOSStub_ab5f {
  strings:
    $key_ab5f = { ff 37 [2] 8b 2f [2] cc 2d [2] 8b 3c [2] c5 30 [2] c9 3a [2] de 31 [2] c5 7f [2] f8 }

  condition:
    any of them
}