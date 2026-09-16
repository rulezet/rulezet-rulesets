rule TTP_XOR_MULT_DOSStub_9a1b {
  strings:
    $key_9a1b = { ce 73 [2] ba 6b [2] fd 69 [2] ba 78 [2] f4 74 [2] f8 7e [2] ef 75 [2] f4 3b [2] c9 }

  condition:
    any of them
}