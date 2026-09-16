rule TTP_XOR_MULT_DOSStub_9a12 {
  strings:
    $key_9a12 = { ce 7a [2] ba 62 [2] fd 60 [2] ba 71 [2] f4 7d [2] f8 77 [2] ef 7c [2] f4 32 [2] c9 }

  condition:
    any of them
}