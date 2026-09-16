rule TTP_XOR_MULT_DOSStub_ab13 {
  strings:
    $key_ab13 = { ff 7b [2] 8b 63 [2] cc 61 [2] 8b 70 [2] c5 7c [2] c9 76 [2] de 7d [2] c5 33 [2] f8 }

  condition:
    any of them
}