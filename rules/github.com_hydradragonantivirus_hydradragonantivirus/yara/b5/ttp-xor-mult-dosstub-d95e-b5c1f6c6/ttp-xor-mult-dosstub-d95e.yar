rule TTP_XOR_MULT_DOSStub_d95e {
  strings:
    $key_d95e = { 8d 36 [2] f9 2e [2] be 2c [2] f9 3d [2] b7 31 [2] bb 3b [2] ac 30 [2] b7 7e [2] 8a }

  condition:
    any of them
}