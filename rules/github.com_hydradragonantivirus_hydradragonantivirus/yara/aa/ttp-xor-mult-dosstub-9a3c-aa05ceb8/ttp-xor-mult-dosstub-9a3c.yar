rule TTP_XOR_MULT_DOSStub_9a3c {
  strings:
    $key_9a3c = { ce 54 [2] ba 4c [2] fd 4e [2] ba 5f [2] f4 53 [2] f8 59 [2] ef 52 [2] f4 1c [2] c9 }

  condition:
    any of them
}