rule TTP_XOR_MULT_DOSStub_9a33 {
  strings:
    $key_9a33 = { ce 5b [2] ba 43 [2] fd 41 [2] ba 50 [2] f4 5c [2] f8 56 [2] ef 5d [2] f4 13 [2] c9 }

  condition:
    any of them
}