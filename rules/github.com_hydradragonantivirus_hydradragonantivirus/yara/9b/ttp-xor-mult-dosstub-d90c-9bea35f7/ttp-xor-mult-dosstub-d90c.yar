rule TTP_XOR_MULT_DOSStub_d90c {
  strings:
    $key_d90c = { 8d 64 [2] f9 7c [2] be 7e [2] f9 6f [2] b7 63 [2] bb 69 [2] ac 62 [2] b7 2c [2] 8a }

  condition:
    any of them
}