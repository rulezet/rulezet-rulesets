rule TTP_XOR_MULT_DOSStub_d95a {
  strings:
    $key_d95a = { 8d 32 [2] f9 2a [2] be 28 [2] f9 39 [2] b7 35 [2] bb 3f [2] ac 34 [2] b7 7a [2] 8a }

  condition:
    any of them
}