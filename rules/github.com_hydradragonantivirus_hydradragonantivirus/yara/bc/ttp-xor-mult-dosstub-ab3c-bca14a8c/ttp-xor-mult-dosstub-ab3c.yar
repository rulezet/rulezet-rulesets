rule TTP_XOR_MULT_DOSStub_ab3c {
  strings:
    $key_ab3c = { ff 54 [2] 8b 4c [2] cc 4e [2] 8b 5f [2] c5 53 [2] c9 59 [2] de 52 [2] c5 1c [2] f8 }

  condition:
    any of them
}