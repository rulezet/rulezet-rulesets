rule TTP_XOR_MULT_DOSStub_9a2e {
  strings:
    $key_9a2e = { ce 46 [2] ba 5e [2] fd 5c [2] ba 4d [2] f4 41 [2] f8 4b [2] ef 40 [2] f4 0e [2] c9 }

  condition:
    any of them
}