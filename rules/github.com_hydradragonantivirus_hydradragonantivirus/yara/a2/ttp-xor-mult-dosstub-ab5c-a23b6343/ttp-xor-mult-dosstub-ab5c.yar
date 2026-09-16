rule TTP_XOR_MULT_DOSStub_ab5c {
  strings:
    $key_ab5c = { ff 34 [2] 8b 2c [2] cc 2e [2] 8b 3f [2] c5 33 [2] c9 39 [2] de 32 [2] c5 7c [2] f8 }

  condition:
    any of them
}