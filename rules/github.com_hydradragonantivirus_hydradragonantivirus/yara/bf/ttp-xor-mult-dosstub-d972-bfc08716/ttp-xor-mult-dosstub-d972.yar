rule TTP_XOR_MULT_DOSStub_d972 {
  strings:
    $key_d972 = { 8d 1a [2] f9 02 [2] be 00 [2] f9 11 [2] b7 1d [2] bb 17 [2] ac 1c [2] b7 52 [2] 8a }

  condition:
    any of them
}