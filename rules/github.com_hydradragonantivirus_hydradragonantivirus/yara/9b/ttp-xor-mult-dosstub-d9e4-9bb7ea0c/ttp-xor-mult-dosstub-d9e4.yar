rule TTP_XOR_MULT_DOSStub_d9e4 {
  strings:
    $key_d9e4 = { 8d 8c [2] f9 94 [2] be 96 [2] f9 87 [2] b7 8b [2] bb 81 [2] ac 8a [2] b7 c4 [2] 8a }

  condition:
    any of them
}