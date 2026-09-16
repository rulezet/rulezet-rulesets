rule TTP_XOR_MULT_DOSStub_d96f {
  strings:
    $key_d96f = { 8d 07 [2] f9 1f [2] be 1d [2] f9 0c [2] b7 00 [2] bb 0a [2] ac 01 [2] b7 4f [2] 8a }

  condition:
    any of them
}