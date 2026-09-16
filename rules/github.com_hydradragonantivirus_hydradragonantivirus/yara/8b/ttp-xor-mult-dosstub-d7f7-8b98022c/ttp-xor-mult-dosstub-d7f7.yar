rule TTP_XOR_MULT_DOSStub_d7f7 {
  strings:
    $key_d7f7 = { 83 9f [2] f7 87 [2] b0 85 [2] f7 94 [2] b9 98 [2] b5 92 [2] a2 99 [2] b9 d7 [2] 84 }

  condition:
    any of them
}