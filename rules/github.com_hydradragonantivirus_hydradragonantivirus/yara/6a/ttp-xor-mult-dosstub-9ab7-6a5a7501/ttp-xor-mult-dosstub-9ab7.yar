rule TTP_XOR_MULT_DOSStub_9ab7 {
  strings:
    $key_9ab7 = { ce df [2] ba c7 [2] fd c5 [2] ba d4 [2] f4 d8 [2] f8 d2 [2] ef d9 [2] f4 97 [2] c9 }

  condition:
    any of them
}