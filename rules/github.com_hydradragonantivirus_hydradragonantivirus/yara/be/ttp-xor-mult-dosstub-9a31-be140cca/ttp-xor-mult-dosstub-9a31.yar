rule TTP_XOR_MULT_DOSStub_9a31 {
  strings:
    $key_9a31 = { ce 59 [2] ba 41 [2] fd 43 [2] ba 52 [2] f4 5e [2] f8 54 [2] ef 5f [2] f4 11 [2] c9 }

  condition:
    any of them
}