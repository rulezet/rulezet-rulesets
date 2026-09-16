rule TTP_XOR_MULT_DOSStub_9a77 {
  strings:
    $key_9a77 = { ce 1f [2] ba 07 [2] fd 05 [2] ba 14 [2] f4 18 [2] f8 12 [2] ef 19 [2] f4 57 [2] c9 }

  condition:
    any of them
}