rule TTP_XOR_MULT_DOSStub_9a46 {
  strings:
    $key_9a46 = { ce 2e [2] ba 36 [2] fd 34 [2] ba 25 [2] f4 29 [2] f8 23 [2] ef 28 [2] f4 66 [2] c9 }

  condition:
    any of them
}