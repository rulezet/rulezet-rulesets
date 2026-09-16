rule TTP_XOR_MULT_DOSStub_d97d {
  strings:
    $key_d97d = { 8d 15 [2] f9 0d [2] be 0f [2] f9 1e [2] b7 12 [2] bb 18 [2] ac 13 [2] b7 5d [2] 8a }

  condition:
    any of them
}