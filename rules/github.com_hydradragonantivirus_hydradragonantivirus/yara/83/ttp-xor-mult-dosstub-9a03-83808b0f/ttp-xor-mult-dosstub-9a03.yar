rule TTP_XOR_MULT_DOSStub_9a03 {
  strings:
    $key_9a03 = { ce 6b [2] ba 73 [2] fd 71 [2] ba 60 [2] f4 6c [2] f8 66 [2] ef 6d [2] f4 23 [2] c9 }

  condition:
    any of them
}