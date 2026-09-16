rule TTP_XOR_MULT_DOSStub_9a71 {
  strings:
    $key_9a71 = { ce 19 [2] ba 01 [2] fd 03 [2] ba 12 [2] f4 1e [2] f8 14 [2] ef 1f [2] f4 51 [2] c9 }

  condition:
    any of them
}