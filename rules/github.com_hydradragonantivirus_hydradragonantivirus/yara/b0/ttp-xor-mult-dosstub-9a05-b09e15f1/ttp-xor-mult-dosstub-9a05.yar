rule TTP_XOR_MULT_DOSStub_9a05 {
  strings:
    $key_9a05 = { ce 6d [2] ba 75 [2] fd 77 [2] ba 66 [2] f4 6a [2] f8 60 [2] ef 6b [2] f4 25 [2] c9 }

  condition:
    any of them
}