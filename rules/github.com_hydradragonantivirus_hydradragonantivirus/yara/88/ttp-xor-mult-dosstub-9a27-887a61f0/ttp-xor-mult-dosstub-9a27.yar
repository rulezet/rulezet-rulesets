rule TTP_XOR_MULT_DOSStub_9a27 {
  strings:
    $key_9a27 = { ce 4f [2] ba 57 [2] fd 55 [2] ba 44 [2] f4 48 [2] f8 42 [2] ef 49 [2] f4 07 [2] c9 }

  condition:
    any of them
}