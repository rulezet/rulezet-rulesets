rule TTP_XOR_MULT_DOSStub_9a5b {
  strings:
    $key_9a5b = { ce 33 [2] ba 2b [2] fd 29 [2] ba 38 [2] f4 34 [2] f8 3e [2] ef 35 [2] f4 7b [2] c9 }

  condition:
    any of them
}