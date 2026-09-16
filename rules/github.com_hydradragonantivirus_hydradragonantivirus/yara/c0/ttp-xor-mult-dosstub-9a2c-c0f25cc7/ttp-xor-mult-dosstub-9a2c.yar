rule TTP_XOR_MULT_DOSStub_9a2c {
  strings:
    $key_9a2c = { ce 44 [2] ba 5c [2] fd 5e [2] ba 4f [2] f4 43 [2] f8 49 [2] ef 42 [2] f4 0c [2] c9 }

  condition:
    any of them
}