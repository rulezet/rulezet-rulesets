rule TTP_XOR_MULT_DOSStub_d97a {
  strings:
    $key_d97a = { 8d 12 [2] f9 0a [2] be 08 [2] f9 19 [2] b7 15 [2] bb 1f [2] ac 14 [2] b7 5a [2] 8a }

  condition:
    any of them
}