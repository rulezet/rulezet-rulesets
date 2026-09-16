rule TTP_XOR_MULT_DOSStub_d7f1 {
  strings:
    $key_d7f1 = { 83 99 [2] f7 81 [2] b0 83 [2] f7 92 [2] b9 9e [2] b5 94 [2] a2 9f [2] b9 d1 [2] 84 }

  condition:
    any of them
}