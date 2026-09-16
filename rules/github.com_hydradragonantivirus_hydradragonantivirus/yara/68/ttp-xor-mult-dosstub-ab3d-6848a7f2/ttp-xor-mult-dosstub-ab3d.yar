rule TTP_XOR_MULT_DOSStub_ab3d {
  strings:
    $key_ab3d = { ff 55 [2] 8b 4d [2] cc 4f [2] 8b 5e [2] c5 52 [2] c9 58 [2] de 53 [2] c5 1d [2] f8 }

  condition:
    any of them
}