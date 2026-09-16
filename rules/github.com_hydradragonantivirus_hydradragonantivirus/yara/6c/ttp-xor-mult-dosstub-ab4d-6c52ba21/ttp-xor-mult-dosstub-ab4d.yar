rule TTP_XOR_MULT_DOSStub_ab4d {
  strings:
    $key_ab4d = { ff 25 [2] 8b 3d [2] cc 3f [2] 8b 2e [2] c5 22 [2] c9 28 [2] de 23 [2] c5 6d [2] f8 }

  condition:
    any of them
}