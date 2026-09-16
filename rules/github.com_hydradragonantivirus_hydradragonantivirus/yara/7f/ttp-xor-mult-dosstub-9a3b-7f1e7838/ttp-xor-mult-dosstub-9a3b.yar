rule TTP_XOR_MULT_DOSStub_9a3b {
  strings:
    $key_9a3b = { ce 53 [2] ba 4b [2] fd 49 [2] ba 58 [2] f4 54 [2] f8 5e [2] ef 55 [2] f4 1b [2] c9 }

  condition:
    any of them
}