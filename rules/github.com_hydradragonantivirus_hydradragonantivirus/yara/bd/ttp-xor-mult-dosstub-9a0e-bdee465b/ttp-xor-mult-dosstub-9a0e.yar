rule TTP_XOR_MULT_DOSStub_9a0e {
  strings:
    $key_9a0e = { ce 66 [2] ba 7e [2] fd 7c [2] ba 6d [2] f4 61 [2] f8 6b [2] ef 60 [2] f4 2e [2] c9 }

  condition:
    any of them
}