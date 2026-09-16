rule TTP_XOR_MULT_DOSStub_d97f {
  strings:
    $key_d97f = { 8d 17 [2] f9 0f [2] be 0d [2] f9 1c [2] b7 10 [2] bb 1a [2] ac 11 [2] b7 5f [2] 8a }

  condition:
    any of them
}