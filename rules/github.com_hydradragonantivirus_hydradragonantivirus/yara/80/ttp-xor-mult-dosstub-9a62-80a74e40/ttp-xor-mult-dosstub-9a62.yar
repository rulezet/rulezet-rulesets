rule TTP_XOR_MULT_DOSStub_9a62 {
  strings:
    $key_9a62 = { ce 0a [2] ba 12 [2] fd 10 [2] ba 01 [2] f4 0d [2] f8 07 [2] ef 0c [2] f4 42 [2] c9 }

  condition:
    any of them
}