rule TTP_XOR_MULT_DOSStub_d932 {
  strings:
    $key_d932 = { 8d 5a [2] f9 42 [2] be 40 [2] f9 51 [2] b7 5d [2] bb 57 [2] ac 5c [2] b7 12 [2] 8a }

  condition:
    any of them
}