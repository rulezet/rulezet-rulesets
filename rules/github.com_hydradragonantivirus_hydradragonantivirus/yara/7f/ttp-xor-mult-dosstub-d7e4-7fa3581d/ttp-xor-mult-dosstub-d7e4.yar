rule TTP_XOR_MULT_DOSStub_d7e4 {
  strings:
    $key_d7e4 = { 83 8c [2] f7 94 [2] b0 96 [2] f7 87 [2] b9 8b [2] b5 81 [2] a2 8a [2] b9 c4 [2] 84 }

  condition:
    any of them
}