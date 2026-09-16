rule TTP_XOR_MULT_DOSStub_9a5c {
  strings:
    $key_9a5c = { ce 34 [2] ba 2c [2] fd 2e [2] ba 3f [2] f4 33 [2] f8 39 [2] ef 32 [2] f4 7c [2] c9 }

  condition:
    any of them
}