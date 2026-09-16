rule TTP_XOR_MULT_DOSStub_9a51 {
  strings:
    $key_9a51 = { ce 39 [2] ba 21 [2] fd 23 [2] ba 32 [2] f4 3e [2] f8 34 [2] ef 3f [2] f4 71 [2] c9 }

  condition:
    any of them
}