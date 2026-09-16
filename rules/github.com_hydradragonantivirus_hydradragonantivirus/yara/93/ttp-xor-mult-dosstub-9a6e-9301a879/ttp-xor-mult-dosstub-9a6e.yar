rule TTP_XOR_MULT_DOSStub_9a6e {
  strings:
    $key_9a6e = { ce 06 [2] ba 1e [2] fd 1c [2] ba 0d [2] f4 01 [2] f8 0b [2] ef 00 [2] f4 4e [2] c9 }

  condition:
    any of them
}