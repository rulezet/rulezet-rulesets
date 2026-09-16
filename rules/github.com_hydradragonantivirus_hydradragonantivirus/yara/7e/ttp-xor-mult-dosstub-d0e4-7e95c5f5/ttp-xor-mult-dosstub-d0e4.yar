rule TTP_XOR_MULT_DOSStub_d0e4 {
  strings:
    $key_d0e4 = { 84 8c [2] f0 94 [2] b7 96 [2] f0 87 [2] be 8b [2] b2 81 [2] a5 8a [2] be c4 [2] 83 }

  condition:
    any of them
}