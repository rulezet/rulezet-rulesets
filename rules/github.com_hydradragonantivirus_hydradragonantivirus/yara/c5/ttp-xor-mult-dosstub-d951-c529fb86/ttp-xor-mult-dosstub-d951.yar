rule TTP_XOR_MULT_DOSStub_d951 {
  strings:
    $key_d951 = { 8d 39 [2] f9 21 [2] be 23 [2] f9 32 [2] b7 3e [2] bb 34 [2] ac 3f [2] b7 71 [2] 8a }

  condition:
    any of them
}