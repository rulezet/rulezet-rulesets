rule TTP_XOR_MULT_DOSStub_d94d {
  strings:
    $key_d94d = { 8d 25 [2] f9 3d [2] be 3f [2] f9 2e [2] b7 22 [2] bb 28 [2] ac 23 [2] b7 6d [2] 8a }

  condition:
    any of them
}