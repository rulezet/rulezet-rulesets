rule TTP_XOR_MULT_DOSStub_d905 {
  strings:
    $key_d905 = { 8d 6d [2] f9 75 [2] be 77 [2] f9 66 [2] b7 6a [2] bb 60 [2] ac 6b [2] b7 25 [2] 8a }

  condition:
    any of them
}