rule TTP_XOR_MULT_DOSStub_d9c7 {
  strings:
    $key_d9c7 = { 8d af [2] f9 b7 [2] be b5 [2] f9 a4 [2] b7 a8 [2] bb a2 [2] ac a9 [2] b7 e7 [2] 8a }

  condition:
    any of them
}