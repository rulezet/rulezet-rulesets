rule TTP_XOR_MULT_DOSStub_ab7f {
  strings:
    $key_ab7f = { ff 17 [2] 8b 0f [2] cc 0d [2] 8b 1c [2] c5 10 [2] c9 1a [2] de 11 [2] c5 5f [2] f8 }

  condition:
    any of them
}