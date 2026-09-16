rule TTP_XOR_MULT_DOSStub_d9e1 {
  strings:
    $key_d9e1 = { 8d 89 [2] f9 91 [2] be 93 [2] f9 82 [2] b7 8e [2] bb 84 [2] ac 8f [2] b7 c1 [2] 8a }

  condition:
    any of them
}