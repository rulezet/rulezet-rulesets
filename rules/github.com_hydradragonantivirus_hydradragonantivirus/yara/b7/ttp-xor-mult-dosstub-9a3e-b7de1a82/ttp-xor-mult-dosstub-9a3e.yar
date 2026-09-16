rule TTP_XOR_MULT_DOSStub_9a3e {
  strings:
    $key_9a3e = { ce 56 [2] ba 4e [2] fd 4c [2] ba 5d [2] f4 51 [2] f8 5b [2] ef 50 [2] f4 1e [2] c9 }

  condition:
    any of them
}