rule TTP_XOR_MULT_DOSStub_9a61 {
  strings:
    $key_9a61 = { ce 09 [2] ba 11 [2] fd 13 [2] ba 02 [2] f4 0e [2] f8 04 [2] ef 0f [2] f4 41 [2] c9 }

  condition:
    any of them
}