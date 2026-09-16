rule TTP_XOR_MULT_DOSStub_9a26 {
  strings:
    $key_9a26 = { ce 4e [2] ba 56 [2] fd 54 [2] ba 45 [2] f4 49 [2] f8 43 [2] ef 48 [2] f4 06 [2] c9 }

  condition:
    any of them
}