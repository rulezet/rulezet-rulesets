rule TTP_XOR_MULT_DOSStub_9a14 {
  strings:
    $key_9a14 = { ce 7c [2] ba 64 [2] fd 66 [2] ba 77 [2] f4 7b [2] f8 71 [2] ef 7a [2] f4 34 [2] c9 }

  condition:
    any of them
}