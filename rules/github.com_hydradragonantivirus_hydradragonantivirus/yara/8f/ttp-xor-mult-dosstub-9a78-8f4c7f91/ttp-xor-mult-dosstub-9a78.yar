rule TTP_XOR_MULT_DOSStub_9a78 {
  strings:
    $key_9a78 = { ce 10 [2] ba 08 [2] fd 0a [2] ba 1b [2] f4 17 [2] f8 1d [2] ef 16 [2] f4 58 [2] c9 }

  condition:
    any of them
}