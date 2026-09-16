rule TTP_XOR_MULT_DOSStub_d96e {
  strings:
    $key_d96e = { 8d 06 [2] f9 1e [2] be 1c [2] f9 0d [2] b7 01 [2] bb 0b [2] ac 00 [2] b7 4e [2] 8a }

  condition:
    any of them
}