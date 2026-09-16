rule TTP_XOR_MULT_DOSStub_ab33 {
  strings:
    $key_ab33 = { ff 5b [2] 8b 43 [2] cc 41 [2] 8b 50 [2] c5 5c [2] c9 56 [2] de 5d [2] c5 13 [2] f8 }

  condition:
    any of them
}