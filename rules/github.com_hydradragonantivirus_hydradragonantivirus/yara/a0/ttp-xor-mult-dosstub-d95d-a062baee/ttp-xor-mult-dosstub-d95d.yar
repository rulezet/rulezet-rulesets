rule TTP_XOR_MULT_DOSStub_d95d {
  strings:
    $key_d95d = { 8d 35 [2] f9 2d [2] be 2f [2] f9 3e [2] b7 32 [2] bb 38 [2] ac 33 [2] b7 7d [2] 8a }

  condition:
    any of them
}