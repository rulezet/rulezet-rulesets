rule TTP_XOR_MULT_DOSStub_ab43 {
  strings:
    $key_ab43 = { ff 2b [2] 8b 33 [2] cc 31 [2] 8b 20 [2] c5 2c [2] c9 26 [2] de 2d [2] c5 63 [2] f8 }

  condition:
    any of them
}