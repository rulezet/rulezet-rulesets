rule TTP_XOR_MULT_DOSStub_9a50 {
  strings:
    $key_9a50 = { ce 38 [2] ba 20 [2] fd 22 [2] ba 33 [2] f4 3f [2] f8 35 [2] ef 3e [2] f4 70 [2] c9 }

  condition:
    any of them
}