rule TTP_XOR_MULT_DOSStub_9a40 {
  strings:
    $key_9a40 = { ce 28 [2] ba 30 [2] fd 32 [2] ba 23 [2] f4 2f [2] f8 25 [2] ef 2e [2] f4 60 [2] c9 }

  condition:
    any of them
}