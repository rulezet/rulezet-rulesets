rule TTP_XOR_MULT_DOSStub_d7f6 {
  strings:
    $key_d7f6 = { 83 9e [2] f7 86 [2] b0 84 [2] f7 95 [2] b9 99 [2] b5 93 [2] a2 98 [2] b9 d6 [2] 84 }

  condition:
    any of them
}