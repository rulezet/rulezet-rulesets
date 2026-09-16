rule TTP_XOR_MULT_DOSStub_9a07 {
  strings:
    $key_9a07 = { ce 6f [2] ba 77 [2] fd 75 [2] ba 64 [2] f4 68 [2] f8 62 [2] ef 69 [2] f4 27 [2] c9 }

  condition:
    any of them
}