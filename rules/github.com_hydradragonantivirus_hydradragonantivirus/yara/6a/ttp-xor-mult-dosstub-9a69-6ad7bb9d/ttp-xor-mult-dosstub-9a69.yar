rule TTP_XOR_MULT_DOSStub_9a69 {
  strings:
    $key_9a69 = { ce 01 [2] ba 19 [2] fd 1b [2] ba 0a [2] f4 06 [2] f8 0c [2] ef 07 [2] f4 49 [2] c9 }

  condition:
    any of them
}