rule TTP_XOR_MULT_DOSStub_d917 {
  strings:
    $key_d917 = { 8d 7f [2] f9 67 [2] be 65 [2] f9 74 [2] b7 78 [2] bb 72 [2] ac 79 [2] b7 37 [2] 8a }

  condition:
    any of them
}