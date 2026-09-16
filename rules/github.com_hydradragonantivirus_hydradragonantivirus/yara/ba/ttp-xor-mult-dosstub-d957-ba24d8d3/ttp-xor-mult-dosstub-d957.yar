rule TTP_XOR_MULT_DOSStub_d957 {
  strings:
    $key_d957 = { 8d 3f [2] f9 27 [2] be 25 [2] f9 34 [2] b7 38 [2] bb 32 [2] ac 39 [2] b7 77 [2] 8a }

  condition:
    any of them
}