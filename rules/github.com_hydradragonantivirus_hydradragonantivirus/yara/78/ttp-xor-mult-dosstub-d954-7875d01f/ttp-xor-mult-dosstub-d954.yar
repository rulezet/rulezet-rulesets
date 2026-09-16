rule TTP_XOR_MULT_DOSStub_d954 {
  strings:
    $key_d954 = { 8d 3c [2] f9 24 [2] be 26 [2] f9 37 [2] b7 3b [2] bb 31 [2] ac 3a [2] b7 74 [2] 8a }

  condition:
    any of them
}