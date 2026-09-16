rule TTP_XOR_MULT_DOSStub_ab1d {
  strings:
    $key_ab1d = { ff 75 [2] 8b 6d [2] cc 6f [2] 8b 7e [2] c5 72 [2] c9 78 [2] de 73 [2] c5 3d [2] f8 }

  condition:
    any of them
}