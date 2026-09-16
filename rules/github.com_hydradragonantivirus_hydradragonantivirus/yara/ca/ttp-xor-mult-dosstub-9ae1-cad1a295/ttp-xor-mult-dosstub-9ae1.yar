rule TTP_XOR_MULT_DOSStub_9ae1 {
  strings:
    $key_9ae1 = { ce 89 [2] ba 91 [2] fd 93 [2] ba 82 [2] f4 8e [2] f8 84 [2] ef 8f [2] f4 c1 [2] c9 }

  condition:
    any of them
}