rule TTP_XOR_MULT_DOSStub_9a0b {
  strings:
    $key_9a0b = { ce 63 [2] ba 7b [2] fd 79 [2] ba 68 [2] f4 64 [2] f8 6e [2] ef 65 [2] f4 2b [2] c9 }

  condition:
    any of them
}