rule TTP_XOR_MULT_DOSStub_9a67 {
  strings:
    $key_9a67 = { ce 0f [2] ba 17 [2] fd 15 [2] ba 04 [2] f4 08 [2] f8 02 [2] ef 09 [2] f4 47 [2] c9 }

  condition:
    any of them
}