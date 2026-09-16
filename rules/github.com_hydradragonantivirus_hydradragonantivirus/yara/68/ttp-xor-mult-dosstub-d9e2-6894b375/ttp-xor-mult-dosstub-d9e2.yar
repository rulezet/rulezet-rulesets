rule TTP_XOR_MULT_DOSStub_d9e2 {
  strings:
    $key_d9e2 = { 8d 8a [2] f9 92 [2] be 90 [2] f9 81 [2] b7 8d [2] bb 87 [2] ac 8c [2] b7 c2 [2] 8a }

  condition:
    any of them
}