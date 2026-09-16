rule TTP_XOR_MULT_DOSStub_ab6f {
  strings:
    $key_ab6f = { ff 07 [2] 8b 1f [2] cc 1d [2] 8b 0c [2] c5 00 [2] c9 0a [2] de 01 [2] c5 4f [2] f8 }

  condition:
    any of them
}