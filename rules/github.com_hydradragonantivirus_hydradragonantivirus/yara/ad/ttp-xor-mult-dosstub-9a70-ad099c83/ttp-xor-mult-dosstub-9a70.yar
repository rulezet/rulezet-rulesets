rule TTP_XOR_MULT_DOSStub_9a70 {
  strings:
    $key_9a70 = { ce 18 [2] ba 00 [2] fd 02 [2] ba 13 [2] f4 1f [2] f8 15 [2] ef 1e [2] f4 50 [2] c9 }

  condition:
    any of them
}