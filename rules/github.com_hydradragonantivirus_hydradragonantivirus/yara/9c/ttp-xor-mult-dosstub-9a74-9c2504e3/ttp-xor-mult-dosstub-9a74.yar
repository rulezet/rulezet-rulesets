rule TTP_XOR_MULT_DOSStub_9a74 {
  strings:
    $key_9a74 = { ce 1c [2] ba 04 [2] fd 06 [2] ba 17 [2] f4 1b [2] f8 11 [2] ef 1a [2] f4 54 [2] c9 }

  condition:
    any of them
}