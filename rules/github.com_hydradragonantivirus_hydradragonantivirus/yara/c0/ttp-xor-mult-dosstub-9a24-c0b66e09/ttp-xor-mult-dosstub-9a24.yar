rule TTP_XOR_MULT_DOSStub_9a24 {
  strings:
    $key_9a24 = { ce 4c [2] ba 54 [2] fd 56 [2] ba 47 [2] f4 4b [2] f8 41 [2] ef 4a [2] f4 04 [2] c9 }

  condition:
    any of them
}