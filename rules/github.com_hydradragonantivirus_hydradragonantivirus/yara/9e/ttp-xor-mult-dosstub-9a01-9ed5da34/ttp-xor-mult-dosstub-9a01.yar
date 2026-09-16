rule TTP_XOR_MULT_DOSStub_9a01 {
  strings:
    $key_9a01 = { ce 69 [2] ba 71 [2] fd 73 [2] ba 62 [2] f4 6e [2] f8 64 [2] ef 6f [2] f4 21 [2] c9 }

  condition:
    any of them
}