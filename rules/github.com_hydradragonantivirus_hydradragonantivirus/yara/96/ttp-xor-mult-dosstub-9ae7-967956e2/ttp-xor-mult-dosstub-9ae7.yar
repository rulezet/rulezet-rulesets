rule TTP_XOR_MULT_DOSStub_9ae7 {
  strings:
    $key_9ae7 = { ce 8f [2] ba 97 [2] fd 95 [2] ba 84 [2] f4 88 [2] f8 82 [2] ef 89 [2] f4 c7 [2] c9 }

  condition:
    any of them
}